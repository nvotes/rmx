use std::path::{Path, PathBuf};
use std::fs;

use git2::build::{CheckoutBuilder, RepoBuilder};
use git2::*;
use tempfile::NamedTempFile;
use walkdir::{DirEntry, WalkDir};

use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;


use crate::util;
use crate::crypto::hashing;
use crate::crypto::hashing::HashBytes;
use crate::crypto::hashing::Hash;
use crate::data::bytes::*;
use crate::bulletinboard::basic::BasicBoard;

#[derive(Serialize, Deserialize)]
struct GitBulletinBoard {
    pub ssh_key_path: String,
    pub url: String,
    pub fs_path: String,
    pub append_only: bool
}

impl BasicBoard for GitBulletinBoard {
    fn list(&self) -> Vec<String> {
       self.list_entries()
    }
    fn get<A: HashBytes + DeserializeOwned + Deser>(&self, target: String, hash: Hash) -> Result<A, String> {
        
        self.get_object(Path::new(&target), hash)
    }
    fn put(&mut self, entries: Vec<(&Path, &Path)>) -> Result<(), String> {
        self.post(entries, "Test")
            .map_err(|e| std::format!("git error {}", e))
    }
    fn get_unsafe(&self, target: &str) -> Option<Vec<u8>> {
        let target_file = Path::new(&self.fs_path).join(target);

        util::read_file_bytes(&target_file)
            .map_err(|e| std::format!("IO error {}", e)).ok()
    }
    /* fn get_config_type(&self, target: &str) -> Option<bool> {
        let bytes = self.data.get(target)?;
        // let config_rug = bincode::deserialize::<Config<Integer, RugGroup>>(bytes);
        let config_rug = Config::<Integer, RugGroup>::deser(bytes);

        // let config_ristretto = bincode::deserialize::<Config<RistrettoPoint, RistrettoGroup>>(bytes);
        let config_ristretto = Config::<RistrettoPoint, RistrettoGroup>::deser(bytes);
        if config_rug.is_ok() {
            Some(true)
        }
        else if config_ristretto.is_ok() {
            Some(false)
        }
        else {
            None
        }
    }
    fn clear(&mut self) {
        self.data.clear();
    }*/
}


impl GitBulletinBoard {

    fn open_or_clone(&self) -> Result<Repository, Error> {    
        if Path::new(&self.fs_path).exists() {
            Repository::open(&self.fs_path)
        }
        else {  
            let co = CheckoutBuilder::new();
            let mut fo = FetchOptions::new();
            let cb = remote_callbacks(&self.ssh_key_path);
            fo.remote_callbacks(cb);    
            RepoBuilder::new()
                .fetch_options(fo)
                .with_checkout(co)
                .clone(&self.url, Path::new(&self.fs_path))
        }
    }
    
    fn list_entries(&self) -> Vec<String> {
        let walker = WalkDir::new(&self.fs_path).min_depth(1).into_iter();
        let entries: Vec<DirEntry> = walker
            .filter_entry(|e| !is_hidden(e))
            .map(|e| e.unwrap())
            .collect();
         
        // filter directories and make relative
        let files = entries.into_iter()
            .filter(|e| !e.file_type().is_dir())
            .map(|e| {
                e.path()
                    .strip_prefix(&self.fs_path).unwrap()
                    .to_str().unwrap().to_string()
            })
            .collect();

        files
    }

    fn get_object<A: HashBytes + DeserializeOwned + Deser>(&self, target_path: 
        &Path, hash: Hash) -> Result<A, String> {

        let target_file = Path::new(&self.fs_path).join(target_path);

        let bytes: Vec<u8> = util::read_file_bytes(&target_file)
            .map_err(|e| std::format!("IO error {}", e))?;

        // let artifact = bincode::deserialize::<A>(&bytes)?;
        let artifact = A::deser(&bytes).map_err(|e| std::format!("serialization error {}", e))?;

        let hashed = hashing::hash(&artifact);
        
        if hashed == hash {
            Ok(artifact)
        }
        else {
            Err("Mismatched hash".to_string())
        }
    }

    fn post(&mut self, files: Vec<(&Path, &Path)>, message: &str) -> Result<(), Error> {
        let repo = self.open_or_clone()?;
        // includes refresh before commit
        self.add_commit_many(&repo, files, message, self.append_only)?;
        self.push(&repo)
    }

    fn add_commit_many(&self, repo: &Repository, files: Vec<(&Path, &Path)>, 
        message: &str, append_only: bool) -> Result<(), Error> {
        let mut entries = vec![];
        for (target, source) in files {
            let next = self.prepare_add(target, source);
            entries.push(next);
        }
        // refresh right before commiting
        self.refresh()?;
        // adding to repo index uses relative path
        add_and_commit(&repo, entries, message, append_only)
    }
    
    fn add_commit(&self, repo: &Repository, target: &Path, source: &Path, message: &str,
        append_only: bool) -> Result<(), Error> {
        
        let entry = self.prepare_add(target, source);
        // refresh right before commiting
        self.refresh()?;
        // adding to repo index uses relative path
        add_and_commit(&repo, vec![entry], message, append_only)
    }

    fn prepare_add(&self, target_path: &Path, source: &Path) -> GitAddEntry {
        let target_file = Path::new(&self.fs_path).join(target_path);
        if target_file.is_file() && target_file.exists() {
            fs::remove_file(&target_file).unwrap();
        }
        let tmp_file = NamedTempFile::new().unwrap();
        let tmp_file_path = tmp_file.path();
        fs::copy(source, tmp_file_path).unwrap();
        
        GitAddEntry {
            tmp_file: tmp_file, 
            fs_path: target_file.to_path_buf(), 
            repo_path: target_path.to_path_buf()
        }
    }

    fn push(&self, repo: &Repository) -> Result<(), Error> {
        let mut options = PushOptions::new();
        options.remote_callbacks(remote_callbacks(&self.ssh_key_path));
        let mut remote = repo.find_remote("origin").unwrap();
        repo.remote_add_push("origin", "refs/heads/master:refs/heads/master").unwrap();
        remote.connect_auth(Direction::Push, Some(remote_callbacks(&self.ssh_key_path)), None)?;
        remote.push(&["refs/heads/master:refs/heads/master"], Some(&mut options))
    }

    // refreshes the local copy with remote updates,
    // preserving local commits, uncommitted changes are discarded.
    // upstream changes only applied in fast forward mode, conflicts cause panic
    fn refresh(&self) -> Result<(), Error> {
        let repo = self.open_or_clone()?;
        let mut remote = repo.find_remote("origin").unwrap();
        let mut fo = FetchOptions::new();
        let cb = remote_callbacks(&self.ssh_key_path);
        fo.remote_callbacks(cb);
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;
    
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        
        let head = repo.head()?;
        let local_commit = repo.reference_to_annotated_commit(&head)?;
        let local_object = repo.find_object(local_commit.id(), None)?;
        repo.reset(&local_object, git2::ResetType::Hard, None)?;
        
        let analysis = repo.merge_analysis(&[&commit])?;
    
        if analysis.0.is_up_to_date() {
            println!("Up to date");
            Ok(())
        }
        else if analysis.0.is_fast_forward() {        
            println!("Requires fast-forward");
            if self.append_only {
                let mut opts = DiffOptions::new();
                let tree_old = repo.find_commit(local_commit.id()).unwrap().tree().unwrap();
                let tree_new = repo.find_commit(commit.id()).unwrap().tree().unwrap();
                
                let diff = repo.diff_tree_to_tree(Some(&tree_old), Some(&tree_new), Some(&mut opts))?;
                for d in diff.deltas() {
                    if d.status() != Delta::Added {
                        return Err(git2::Error::from_str(&format!("Found non-add git delta in append-only mode: {:?}", d)))
                    }
                }
            }
            
            let refname = format!("refs/heads/master");
            let mut r = repo.find_reference(&refname)?;
            fast_forward(&repo, &mut r, &commit)?;
            Ok(())
        }
        else {
            // Err(git2::Error::from_str("Unexpected merge required"))
            panic!("Unexpected merge required");
        }
    }

    // syncs the working copy to match that of the remote
    // local commits and working copy are discarded
    // ignore or untracked files are not affected
    fn sync_down(&self, repo: &Repository) -> Result<(), Error> {
        let mut remote = repo.find_remote("origin")?;
        let mut fo = FetchOptions::new();
        fo.remote_callbacks(remote_callbacks(&self.ssh_key_path));
        fo.download_tags(git2::AutotagOption::All);
        remote.fetch(&["master"], Some(&mut fo), None)?;
        let fetch_head = repo.find_reference("FETCH_HEAD")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        let object = repo.find_object(commit.id(), None)?;
        repo.reset(&object, git2::ResetType::Hard, None)
    }

    // clears the repository of any files, and pushes
    // note that files in the working directory are not eliminated
    // and would be considered untracked, so a sync_down will not delete them
    fn __delete(&self) -> Result<(), Error> {
        let repo = self.open_or_clone()?;
        let mut index = repo.index()?;
        index.clear()?;

        let oid = index.write_tree()?;
        let signature = Signature::now("rmx", "rmx@foo.bar")?;
        let parent_commit = find_last_commit(&repo)?;
        let tree = repo.find_tree(oid)?;

        index.write()?;
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "reset",
            &tree,
            &[&parent_commit])?;
        
        self.push(&repo)
    }
}

struct GitAddEntry {
    tmp_file: NamedTempFile,
    fs_path: PathBuf,
    repo_path: PathBuf
}

fn find_last_commit(repo: &Repository) -> Result<Commit, Error> {
    let obj = repo.head()?.resolve()?.peel(ObjectType::Commit)?;
    match obj.into_commit() {
        Ok(c) => Ok(c),
        _ => Err(git2::Error::from_str("Couldn't find commit"))
    }
} 

fn fast_forward(
    repo: &Repository,
    lb: &mut git2::Reference,
    rc: &git2::AnnotatedCommit,
) -> Result<(), Error> {
    let name = match lb.name() {
        Some(s) => s.to_string(),
        None => String::from_utf8_lossy(lb.name_bytes()).to_string(),
    };
    let msg = format!("Fast-Forward: Setting {} to id: {}", name, rc.id());
    lb.set_target(rc.id(), &msg)?;
    repo.set_head(&name)?;
    repo.checkout_head(Some(
        git2::build::CheckoutBuilder::default().force()
    ))?;
    Ok(())
}

fn add_and_commit(repo: &Repository, entries: Vec<GitAddEntry>, message: &str, 
    append_only: bool) -> Result<(), Error> {
    
    let mut index = repo.index()?;
    for e in entries {
        println!("{:?} -> {:?}", e.tmp_file.path(), e.fs_path);
        fs::rename(e.tmp_file.path(), &e.fs_path).unwrap();
        index.add_path(&e.repo_path)?;
    }
    let oid = index.write_tree()?;
    let signature = Signature::now("rmx", "rmx@foo.bar")?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    
    if append_only {
        let mut opts = DiffOptions::new();
        let diff = repo.diff_tree_to_index(Some(&parent_commit.tree()?), Some(&index), Some(&mut opts))?;
        for d in diff.deltas() {
            if d.status() != Delta::Added {
                return Err(git2::Error::from_str(&format!("Found non-add git delta in append-only mode: {:?}", d)))     
            }
        }
    }

    index.write()?;
    repo.commit(Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &[&parent_commit])?;
    Ok(())
}

fn remote_callbacks<'a>(ssh_path: &'a str) -> RemoteCallbacks<'a> {
    let mut cb = RemoteCallbacks::new();
    let path = Path::new(ssh_path);
    cb.credentials(move |_, _, _| {
        let credentials = 
            Cred::ssh_key(
                "git", 
                None, 
                path,
                None
            ).expect("Could not create credentials object");
    
    
        Ok(credentials)
    });

    cb
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry.file_name()
         .to_str()
         .map(|s| s.starts_with("."))
         .unwrap_or(false)
}

fn read_config() -> GitBulletinBoard {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/test/git_bb.json");
    let cfg = fs::read_to_string(d).unwrap();
    let g: GitBulletinBoard = serde_json::from_str(&cfg).unwrap();

    g
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use std::fs;
    use std::path::{Path};
    
    use crate::bulletinboard::git::*;
    use crate::util;
    
    #[test]
    #[serial]
    fn test_open_or_clone() {
        
        let g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        
        let dir = Path::new(&g.fs_path);
        assert!(dir.exists() && dir.is_dir());
    }

    #[test]
    #[serial]
    fn test_refresh() {
        let g = read_config();
        g.open_or_clone().unwrap();
        
        let dir = Path::new(&g.fs_path);
        assert!(dir.exists() && dir.is_dir());

        g.refresh().unwrap();
    }

    #[test]
    #[serial]
    fn test_post() {
        let mut g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let added = util::create_random_file("/tmp");
        let name = Path::new(
            added.file_name().unwrap().to_str().unwrap()
        );
        
        g.post(vec![(name, &added)], "new file").unwrap();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list();
        assert!(files.contains(&name.to_str().unwrap().to_string()));
    }

    #[test]
    #[serial]
    fn test_append_only() {
        let mut g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        
        // add new file
        let added = util::create_random_file("/tmp");
        let name = Path::new(
            added.file_name().unwrap().to_str().unwrap()
        );
        g.post(vec![(name, &added)], "new file").unwrap();
        
        // create 2nd repo after creating file but before making modification
        let mut g2 = read_config();
        g2.fs_path.push_str("_");
        fs::remove_dir_all(&g2.fs_path).ok();
        g2.open_or_clone().unwrap();

        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list();
        assert!(files.contains(&name.to_str().unwrap().to_string()));
        
        let modify = added.to_str().unwrap();
        
        util::modify_file(&modify);
        let mut result = g.post(vec![(name, &added)], "file modification");
        // cannot modify upstream in append_only mode
        assert!(result.is_err());
        
        g.append_only = false;
        result = g.post(vec![(name, &added)], "file modification");
        assert!(result.is_ok());

        g2.append_only = true;
        result = g2.refresh();
        // cannot modify downstream in append_only mode
        assert!(result.is_err());

        g2.append_only = false;
        result = g2.refresh();
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn test_delete() {
        let mut g = read_config();
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        g.__delete().unwrap();
        
        fs::remove_dir_all(&g.fs_path).ok();
        g.open_or_clone().unwrap();
        let files = g.list();
        assert!(files.len() == 0);
    }
}
