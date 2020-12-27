use std::marker::PhantomData;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, PublicKey as SPublicKey};
use uuid::Uuid;
use serde::de::DeserializeOwned;

use rmx::statement::SignedStatement;
use rmx::artifact::*;
use rmx::elgamal::PublicKey;
use rmx::hashing;
use rmx::group::Group;
use rmx::arithm::Element;
use rmx::rug_b::*;
use rmx::ristretto_b::*;
use rmx::bb::BulletinBoard;
use rmx::bb::Names;
use rmx::memory_bb::*;
use rmx::protocol::*;
use rmx::util;
use rmx::localstore::*;
use rmx::trustee::Trustee;

use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{LinearLayout, TextView, Panel, ScrollView};
use cursive::theme::{Color, PaletteColor, Theme};
use cursive::view::ScrollStrategy;
use cursive::Cursive;
use cursive::utils::markup::StyledString;
use cursive::theme::BaseColor;

use regex::Regex;
use simplelog::*;
use log::info;

type DemoArc<E, G> = Arc<Mutex<Demo<E, G>>>;

struct Demo<E: Element, G> {
    pub cb_sink: cursive::CbSink,
    trustees: Vec<Protocol<E, G, MemoryBulletinBoard<E, G>>>,
    bb_keypair: Keypair,
    config: rmx::artifact::Config<E, G>,
    board: MemoryBulletinBoard<E, G>,
    all_plaintexts: Vec<Vec<E::Plaintext>>,
    ballots: u32
}
impl<E: Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned> Demo<E, G> {
    fn new(sink: cursive::CbSink, group: &G, trustees: u32, contests: u32, ballots: u32) -> Demo<E, G> {
        let local1 = "/tmp/local";
        let local2 = "/tmp/local2";
        let local_path = Path::new(&local1);
        fs::remove_dir_all(local_path).ok();
        fs::create_dir(local_path).ok();
        let local_path = Path::new(&local2);
        fs::remove_dir_all(local_path).ok();
        fs::create_dir(local_path).ok();
        
        let mut trustee_pks = Vec::new();
        let mut prots = Vec::new();
        
        for i in 0..trustees {
            let local = format!("/tmp/local{}", i);
            let local_path = Path::new(&local);
            fs::remove_dir_all(local_path).ok();
            fs::create_dir(local_path).ok();
            let trustee: Trustee<E, G> = Trustee::new(local.to_string());
            trustee_pks.push(trustee.keypair.public);
            let prot: Protocol<E, G, MemoryBulletinBoard<E, G>> = Protocol::new(trustee);
            prots.push(prot);

        }
        let mut csprng = OsRng;
        let bb_keypair = Keypair::generate(&mut csprng);
        let mut bb = MemoryBulletinBoard::<E, G>::new();
        let cfg = gen_config(group, contests, trustee_pks, bb_keypair.public);
        let cfg_b = bincode::serialize(&cfg).unwrap();
        let tmp_file = util::write_tmp(cfg_b).unwrap();
        bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));

        Demo {
            cb_sink: sink,
            trustees: prots,
            bb_keypair: bb_keypair,
            config: cfg,
            board: bb,
            all_plaintexts: vec![],
            ballots: ballots
        }
    }
    
    fn add_ballots(&mut self) {
        for i in 0..self.config.contests {
            let pk_b = self.board.get_unsafe(MemoryBulletinBoard::<E, G>::public_key(i, 0));
            let ballots_b = self.board.get_unsafe(MemoryBulletinBoard::<E, G>::ballots(i));
            if pk_b.is_some() && ballots_b.is_none() {
                info!(">> Adding {} ballots..", self.ballots);
                let pk: PublicKey<E, G> = bincode::deserialize(pk_b.unwrap()).unwrap();
                
                let (plaintexts, ciphertexts) = util::random_encrypt_ballots(self.ballots as usize, &pk);
                self.all_plaintexts.push(plaintexts);
                
                let ballots = Ballots { ciphertexts };
                let ballots_b = bincode::serialize(&ballots).unwrap();
                let ballots_h = hashing::hash(&ballots);
                let cfg_h = hashing::hash(&self.config);
                let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &self.bb_keypair);
                
                let ss_b = bincode::serialize(&ss).unwrap();
                
                let f1 = util::write_tmp(ballots_b).unwrap();
                let f2 = util::write_tmp(ss_b).unwrap();
                
                self.board.add_ballots(&BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()), i);
                info!(">> OK");
            }
            else {
                info!("Cannot add ballots for contest=[{}] at this time (no pk yet?)", i);
            }
        }
    }
    fn check_plaintexts(&self) {
        for i in 0..self.config.contests {
            if let Some(decrypted_b) = self.board.get_unsafe(MemoryBulletinBoard::<E, G>::plaintexts(i, 0)) {
                let decrypted: Plaintexts<E> = bincode::deserialize(decrypted_b).unwrap();
                let decoded: Vec<E::Plaintext> = decrypted.plaintexts.iter().map(|p| {
                    self.config.group.decode(&p)
                }).collect();
                let p1: HashSet<&E::Plaintext> = HashSet::from_iter(self.all_plaintexts[i as usize].iter().clone());
                let p2: HashSet<&E::Plaintext> = HashSet::from_iter(decoded.iter().clone());
                
                info!(">> Checking plaintexts contest=[{}]...", i);
                assert!(p1 == p2);
                info!(">> OK");
            }
            else {
                info!("Cannot check plaintexts for contest=[{}], no decryptions yet", i);
            }
            
        }
    }
    fn process_facts(&mut self, t: usize) -> Facts {
        let trustee = &self.trustees[t];
        trustee.process_facts(&mut self.board)
    }
    fn run(&mut self, facts: Facts, t: usize) -> u32 {
        let trustee = &self.trustees[t];
        trustee.run(facts, &mut self.board)
    }
    fn writer(&self) -> DemoLogSink {
        DemoLogSink {
            cb_sink: self.cb_sink.clone(),
            buffer: String::new(),
            target: String::from("0")
        }
    }
    fn status(&self, status: String) {
        self.cb_sink.send(Box::new( 
            move |s: &mut cursive::Cursive| {

            s.call_on_name("status", |view: &mut TextView| {
                let styled = if status == "Ready".to_string() {
                    StyledString::styled(status, Color::Light(BaseColor::Green))
                }
                else {
                    StyledString::styled(status, Color::Light(BaseColor::Yellow))
                };
                view.set_content(styled);
            });
        })).unwrap();
    }
    fn done(&self, trustee: u32) {
        self.cb_sink.send(Box::new( 
            move |s: &mut cursive::Cursive| {

            s.call_on_name(&trustee.to_string(), |view: &mut ScrollView<TextView>| {
                let current = view.get_inner_mut().get_content();
                let t = String::from(current.source());
                drop(current);
                view.get_inner_mut().set_content(StyledString::styled(t, Color::Light(BaseColor::Green)));
            });
        })).unwrap();
        self.status(String::from("Ready"));
    }
}


#[test]
fn demo_tui() {
    let mut n: u32 = 0;
    let mut siv = cursive::default();
    // let group = RugGroup::default();
    let group = RistrettoGroup;
    let trustees: u32 = 3;
    let contests = 3;
    let ballots = 10000;
    let demo = Demo::new(siv.cb_sink().clone(), &group, trustees, contests, ballots);
    CombinedLogger::init(
        vec![
            // TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed),
            WriteLogger::new(LevelFilter::Warn, simplelog::Config::default(), File::create("/tmp/my.log").unwrap()),
            WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), demo.writer()),
        ]
    ).unwrap();
    
    let demo_arc_run = Arc::new(Mutex::new(
        demo
    ));
    let demo_arc_ballots = Arc::clone(&demo_arc_run);
    let demo_arc_verify = Arc::clone(&demo_arc_run);
    let demo_arc_artifacts = Arc::clone(&demo_arc_run);
    
    let theme = custom_theme_from_cursive(&siv);
    siv.set_theme(theme);
    
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let init_text = format!("Build: {}\nGroup: {}\nTrustees: {}\nContests: {}\nBallots: {}", 
        build, util::type_name_of(&group), trustees, contests, ballots);
    
    let mut h_layout = LinearLayout::horizontal();
    let mut layout = LinearLayout::vertical();
    for i in 0..trustees {
        let title = format!("Trustee {}", i);
        let text = "";    
        layout = layout.child(Panel::new(
            TextView::new(text)
                .scrollable()
                .scroll_strategy(ScrollStrategy::StickToBottom)
                .with_name(&i.to_string())
            )
            .title(title)
            .title_position(HAlign::Left)
            .full_width()
            .full_height()
        );
    }
    
    layout = layout.child(
        LinearLayout::horizontal()
            .child(Panel::new(
                TextView::new("[s Step] [b Add ballots] [c Check plaintexts] [i info] [q Quit]")
            )
            .title("Commands")
            .title_position(HAlign::Left)
            .fixed_height(3)
            .full_width())
            .child(Panel::new(
                TextView::new(StyledString::styled("Ready", Color::Light(BaseColor::Green)))
                .h_align(HAlign::Left)
                .with_name("status")
            )
            .fixed_width(12))
    );
    h_layout.add_child(layout);
    h_layout.add_child(Panel::new(
        TextView::new(init_text.clone())
            .scrollable()
            .scroll_strategy(ScrollStrategy::StickToBottom)
            .with_name("facts"))
        .title("Facts")
        .title_position(HAlign::Left)
        .fixed_width(95)
        .full_height()
    );
    // siv.add_fullscreen_layer(h_layout);
    siv.add_layer(h_layout);
    siv.add_global_callback('q', |s| s.quit());
    siv.add_global_callback('s', move |s| {
        let guard = Arc::clone(&demo_arc_run);
        if guard.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            s.call_on_name(&"facts".to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            step_t(Arc::clone(&demo_arc_run), n);
            n = (n + 1) % trustees;
        }
    });
    siv.add_global_callback('b', move |s| {
        let guard = Arc::clone(&demo_arc_ballots);
        if guard.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            ballots_t(Arc::clone(&demo_arc_ballots), 0);
        }
    });
    siv.add_global_callback('c', move |s| {
        let guard = Arc::clone(&demo_arc_verify);
        if guard.try_lock().is_ok() {
            s.call_on_name(&n.to_string(), |view: &mut ScrollView<TextView>| {
                view.get_inner_mut().set_content("");
            });
            check_t(Arc::clone(&demo_arc_verify), 0);
        }
    });
    siv.add_global_callback('i', move |s| {
        let text = init_text.clone();
        let guard = Arc::clone(&demo_arc_artifacts);
        let demo = guard.lock().unwrap();
        let mut artifacts = demo.board.list();
        artifacts.sort();
        let artifacts = artifacts.join("\n");
        
        s.call_on_name("facts", |view: &mut ScrollView<TextView>| {
            view.get_inner_mut().set_content(text);
            view.get_inner_mut().append("\n\nArtifacts:\n");
            view.get_inner_mut().append(artifacts);
        });
    });
    
    siv.run();
}

fn step_t<E: 'static + Element + DeserializeOwned + std::cmp::PartialEq, G: 'static + Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    std::thread::spawn(move || {
        step(Arc::clone(&demo_arc), t)
    });
}

fn ballots_t<E: 'static + Element + DeserializeOwned + std::cmp::PartialEq, G: 'static + Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    std::thread::spawn(move || {
        ballots(Arc::clone(&demo_arc), t)
    });
}

fn check_t<E: 'static + Element + DeserializeOwned + std::cmp::PartialEq, G: 'static + Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    std::thread::spawn(move || {
        check(Arc::clone(&demo_arc), t)
    });
}

fn step<E: 'static + Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    let mut demo = demo_arc.lock().unwrap();
    demo.status(String::from("Working..."));
    info!("set_panel=[facts]");
    let facts = demo.process_facts(t as usize);
    info!("set_panel=[{}]", t);
    demo.run(facts, t as usize);
    demo.done(t);
}

fn ballots<E: 'static + Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    let mut demo = demo_arc.lock().unwrap();
    demo.status(String::from("Working..."));
    info!("set_panel=[{}]", t);
    demo.add_ballots();
    demo.done(t);
}

fn check<E: 'static + Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned>(demo_arc: DemoArc<E, G>, t: u32) {
    let demo = demo_arc.lock().unwrap();
    demo.status(String::from("Working..."));
    info!("set_panel=[{}]", t);
    demo.check_plaintexts();
    demo.done(t);
}


#[test]
fn demo_rug() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed)
        ]
    ).unwrap();
    let group = RugGroup::default();
    demo(group);
}

#[test]
fn demo_ristretto() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed)
        ]
    ).unwrap();
    let group = RistrettoGroup;
    demo(group);
}

fn demo<E: Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned>(group: G) {
    
    let local1 = "/tmp/local";
    let local2 = "/tmp/local2";
    let local_path = Path::new(&local1);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();
    let local_path = Path::new(&local2);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();

    let trustee1: Trustee<E, G> = Trustee::new(local1.to_string());
    let trustee2: Trustee<E, G> = Trustee::new(local2.to_string());
    let mut csprng = OsRng;
    let bb_keypair = Keypair::generate(&mut csprng);
    let mut bb = MemoryBulletinBoard::<E, G>::new();
    
    let mut trustee_pks = Vec::new();
    trustee_pks.push(trustee1.keypair.public);
    trustee_pks.push(trustee2.keypair.public);
    
    let contests = 3;
    let cfg = gen_config(&group, contests, trustee_pks, bb_keypair.public);
    let cfg_b = bincode::serialize(&cfg).unwrap();
    let tmp_file = util::write_tmp(cfg_b).unwrap();
    bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));
    
    let prot1: Protocol<E, G, MemoryBulletinBoard<E, G>> = Protocol::new(trustee1);
    let prot2: Protocol<E, G, MemoryBulletinBoard<E, G>> = Protocol::new(trustee2);

    // mix position 0
    prot1.step(&mut bb);
    // verify mix position 0
    prot2.step(&mut bb);

    // nothing
    prot1.step(&mut bb);
    // mix position 1
    prot2.step(&mut bb);

    // check mix position 1
    prot1.step(&mut bb);
    // partial decryptions
    prot2.step(&mut bb);

    // partial decryptions
    prot1.step(&mut bb);
    // nothing
    prot2.step(&mut bb);

    // combine decryptions
    prot1.step(&mut bb);
    
    let mut all_plaintexts = Vec::with_capacity(contests as usize);
    
    println!("=================== ballots ===================");
    for i in 0..contests {
        let pk_b = bb.get_unsafe(MemoryBulletinBoard::<E, G>::public_key(i, 0)).unwrap();
        let pk: PublicKey<E, G> = bincode::deserialize(pk_b).unwrap();
        
        let (plaintexts, ciphertexts) = util::random_encrypt_ballots(100, &pk);
        all_plaintexts.push(plaintexts);
        let ballots = Ballots { ciphertexts };
        let ballots_b = bincode::serialize(&ballots).unwrap();
        let ballots_h = hashing::hash(&ballots);
        let cfg_h = hashing::hash(&cfg);
        let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &bb_keypair);
        
        let ss_b = bincode::serialize(&ss).unwrap();
        
        let f1 = util::write_tmp(ballots_b).unwrap();
        let f2 = util::write_tmp(ss_b).unwrap();
        println!(">> Adding {} ballots", ballots.ciphertexts.len());
        bb.add_ballots(&BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()), i);
    }
    println!("===============================================");

    // mix position 0
    prot1.step(&mut bb);
    // verify mix position 0
    prot2.step(&mut bb);

    // nothing
    prot1.step(&mut bb);
    // mix position 1
    prot2.step(&mut bb);

    // check mix position 1
    prot1.step(&mut bb);
    // partial decryptions
    prot2.step(&mut bb);

    // partial decryptions
    prot1.step(&mut bb);
    // nothing
    prot2.step(&mut bb);

    // combine decryptions
    prot1.step(&mut bb);

    for i in 0..contests {
        let decrypted_b = bb.get_unsafe(MemoryBulletinBoard::<E, G>::plaintexts(i, 0)).unwrap();
        let decrypted: Plaintexts<E> = bincode::deserialize(decrypted_b).unwrap();
        let decoded: Vec<E::Plaintext> = decrypted.plaintexts.iter().map(|p| {
            group.decode(&p)
        }).collect();
        let p1: HashSet<&E::Plaintext> = HashSet::from_iter(all_plaintexts[i as usize].iter().clone());
        let p2: HashSet<&E::Plaintext> = HashSet::from_iter(decoded.iter().clone());
        
        print!("Checking plaintexts contest=[{}]...", i);
        assert!(p1 == p2);
        println!("Ok");
    }
}

struct DemoLogSink {
    pub cb_sink: cursive::CbSink,
    pub buffer: String,
    target: String
}
impl std::io::Write for DemoLogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let re = Regex::new("set_panel=\\[([a-z0-9]+)\\]").unwrap();
        
        let string = String::from(std::str::from_utf8(&buf).unwrap());
        self.buffer.push_str(&string);
        if self.buffer.contains("\n") {
            let split: Vec<&str> = self.buffer.split("\n").collect();
            let items = split.len();
            let head = &split[0..items - 1];
            
            for next in head {
                if let Some(captures) = re.captures(next) {
                    let capture = captures.get(1).unwrap().as_str();
                    let target = self.target.clone();
                    self.cb_sink.send(Box::new(
                        move |s: &mut cursive::Cursive| {
                            s.call_on_name(&target, |view: &mut ScrollView<TextView>| {
                            let current = view.get_inner_mut().get_content();
                            let t = String::from(current.source());
                            drop(current);
                            view.get_inner_mut().set_content(t);
                        });
                    }))
                    .unwrap();
                    self.target = capture.to_string();
                }
                else {
                    self.send_line(next.to_string());
                }                
            }
            self.buffer = split[items - 1].to_string();
        }

        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DemoLogSink {
    fn send_line(&self, line: String) {
        let line = format!("{}\n", line);
        let target = self.target.clone();
        self.cb_sink.send(Box::new( 
            move |s: &mut cursive::Cursive| {

            s.call_on_name(&target, |view: &mut ScrollView<TextView>| {
                let styled = StyledString::styled(line, Color::Light(BaseColor::Yellow));
                view.get_inner_mut().append(styled);
                view.scroll_to_bottom();
            });
        }))
        .unwrap();
    }
}

fn gen_config<E: Element, G: Group<E>>(group: &G, contests: u32, trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey) -> rmx::artifact::Config<E, G> {

    let id = Uuid::new_v4();

    let cfg = rmx::artifact::Config {
        id: id.as_bytes().clone(),
        group: group.clone(),
        contests: contests, 
        ballotbox: ballotbox_pk, 
        trustees: trustee_pks,
        phantom_e: PhantomData
    };

    cfg
}

fn custom_theme_from_cursive(siv: &Cursive) -> Theme {
    let mut theme = siv.current_theme().clone();

    theme.palette[PaletteColor::Background] = Color::TerminalDefault;
    theme.palette[PaletteColor::Primary] = Color::Rgb(170, 170, 170);
    theme.palette[PaletteColor::View] = Color::TerminalDefault;

    theme
}