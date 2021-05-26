#![allow(clippy::too_many_arguments)]
use log::info;

use crate::bulletinboard::BulletinBoard;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::data::artifact::*;
use crate::protocol::statement::*;
use crate::protocol::trustee::Trustee;
use crate::protocol::trustee::TrusteeError;

use crate::crypto::elgamal::PrivateKey;
use crate::crypto::hashing;
use crate::crypto::hashing::Hash;
use crate::crypto::keymaker::Keymaker;
use crate::crypto::shuffler::*;
use crate::protocol::logic::Hashes;
use crate::protocol::predicates::Act;
use crate::util::short;

impl<E: Element, G: Group<E>> Trustee<E, G> {
    pub(crate) fn check_config<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        info!(">> Action: checking config..");
        // FIXME validate the config somehow
        let ss = SignedStatement::config(&cfg_h, &self.keypair);
        let stmt_path = self.work_cache.set_config_stmt(&action, &ss)?;
        board.add_config_stmt(&stmt_path, self_index)?;
        info!(">> OK");
        Ok(())
    }

    pub(crate) fn post_share<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        info!(
            ">> Action: Computing shares (contest=[{}], self=[{}])..",
            contest, self_index
        );
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;

        let share = self.gen_share(&cfg.group, &self.get_label(&cfg, contest));
        let share_h = hashing::hash(&share);
        let ss = SignedStatement::keyshare(&cfg_h, &share_h, contest, &self.keypair);
        let share_path = self.work_cache.set_share(&action, share, &ss)?;

        board.add_share(&share_path, contest, self_index)?;
        info!(">> OK");

        Ok(())
    }

    pub(crate) fn combine_shares<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        share_hs: Hashes,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        info!(
            ">> Action: Combining shares (contest=[{}], self=[{}])..",
            contest, self_index
        );
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;
        let hashes = clear_zeroes(&share_hs);
        assert!(hashes.len() == cfg.trustees.len());
        let pk = self
            .get_pk(board, hashes, &cfg, contest)
            .ok_or_else(|| TrusteeError::Msg("Could not build pk".to_string()))?;
        let pk_h = hashing::hash(&pk);
        let ss = SignedStatement::public_key(&cfg_h, &pk_h, contest, &self.keypair);

        let pk_path = self.work_cache.set_pk(&action, pk, &ss)?;
        board.set_pk(&pk_path, contest)?;
        info!(">> OK");

        Ok(())
    }

    pub(crate) fn check_pk<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        pk_h: Hash,
        share_hs: Hashes,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        info!(
            ">> Action: Verifying pk (contest=[{}], self=[{}])..",
            contest, self_index
        );
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;
        let hashes = clear_zeroes(&share_hs);
        assert!(hashes.len() == cfg.trustees.len());
        let pk = self
            .get_pk(board, hashes, &cfg, contest)
            .ok_or_else(|| TrusteeError::Msg("Could not build pk".to_string()))?;
        let pk_h_ = hashing::hash(&pk);
        assert!(pk_h == pk_h_);
        let ss = SignedStatement::public_key(&cfg_h, &pk_h, contest, &self.keypair);

        let pk_stmt_path = self.work_cache.set_pk_stmt(&action, &ss)?;
        board.set_pk_stmt(&pk_stmt_path, contest, self_index)?;
        info!(">> OK");

        Ok(())
    }

    pub(crate) fn mix<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        ballots_or_mix_h: Hash,
        pk_h: Hash,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        info!(
            ">> Computing mix (contest=[{}], self=[{}])..",
            contest, self_index
        );
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;
        let ciphertexts = self
            .get_mix_src(board, contest, self_index, ballots_or_mix_h)
            .ok_or_else(|| TrusteeError::Msg("Could not find source ciphertexts".to_string()))?;
        let pk = board
            .get_pk(contest, pk_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find pk".to_string()))?;

        let group = &cfg.group;
        let hs = generators(ciphertexts.len() + 1, group, contest, cfg.id.to_vec());

        let exp_hasher = &*group.exp_hasher();
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: exp_hasher,
        };

        let now_ = std::time::Instant::now();
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&ciphertexts);
        let proof = shuffler.gen_proof(
            &ciphertexts,
            &e_primes,
            &rs,
            &perm,
            &self.get_label(&cfg, contest),
        );
        // assert!(shuffler.check_proof(&proof, &ciphertexts, &e_primes));
        let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
        info!("Shuffle + Proof ({:.1} ciphertexts/s)", 1000.0 * rate);

        let mix = Mix {
            mixed_ballots: e_primes,
            proof,
        };
        let mix_h = hashing::hash(&mix);

        let ss = SignedStatement::mix(
            &cfg_h,
            &mix_h,
            &ballots_or_mix_h,
            None,
            contest,
            &self.keypair,
        );

        let now_ = std::time::Instant::now();
        let mix_path = self.work_cache.set_mix(&action, mix, &ss)?;
        let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
        info!("IO Write ({:.1} ciphertexts/s)", 1000.0 * rate);

        board.add_mix(&mix_path, contest, self_index)?;
        info!(
            ">> Mix generated {:?} <- {:?}",
            short(&mix_h),
            short(&ballots_or_mix_h)
        );

        Ok(())
    }

    pub(crate) fn check_mix<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        trustee: u32,
        mix_h: Hash,
        ballots_h: Hash,
        pk_h: Hash,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;

        info!(
            ">> Action:: Verifying mix (contest=[{}], self=[{}])..",
            contest, self_index
        );

        let mix = board
            .get_mix(contest, trustee, mix_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find mix".to_string()))?;

        let ciphertexts = self
            .get_mix_src(board, contest, trustee, ballots_h)
            .ok_or_else(|| TrusteeError::Msg("Could not find source ciphertexts".to_string()))?;
        let pk = board
            .get_pk(contest, pk_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find pk".to_string()))?;
        let group = &cfg.group;

        let hs = generators(ciphertexts.len() + 1, group, contest, cfg.id.to_vec());
        let exp_hasher = &*group.exp_hasher();
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: exp_hasher,
        };
        let proof = mix.proof;
        info!(
            "Verifying shuffle {:?} <- {:?}",
            short(&mix_h),
            short(&ballots_h)
        );

        let now_ = std::time::Instant::now();
        assert!(shuffler.check_proof(
            &proof,
            &ciphertexts,
            &mix.mixed_ballots,
            &self.get_label(&cfg, contest)
        ));
        let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
        info!("Check proof ({:.1} ciphertexts/s)", 1000.0 * rate);

        let ss = SignedStatement::mix(
            &cfg_h,
            &mix_h,
            &ballots_h,
            Some(trustee),
            contest,
            &self.keypair,
        );
        let mix_path = self.work_cache.set_mix_stmt(&action, &ss)?;
        board.add_mix_stmt(&mix_path, contest, self_index, trustee)?;

        info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);

        Ok(())
    }

    pub(crate) fn partial_decrypt<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        mix_h: Hash,
        share_h: Hash,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        info!(
            ">> Action: Computing partial decryptions (contest=[{}], self=[{}])..",
            contest, self_index
        );
        let now_ = std::time::Instant::now();

        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;

        let mix = board
            .get_mix(contest, (cfg.trustees.len() - 1) as u32, mix_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find mix".to_string()))?;

        let share = board
            .get_share(contest, self_index, share_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find share".to_string()))?;

        let encrypted_sk = share.encrypted_sk;
        let sk: PrivateKey<E, G> =
            PrivateKey::from_encrypted(self.symmetric, encrypted_sk, &cfg.group);
        let keymaker = Keymaker::from_sk(sk, &cfg.group);

        let (decs, proofs) =
            keymaker.decryption_factor_many(&mix.mixed_ballots, &self.get_label(&cfg, contest));
        let rate = mix.mixed_ballots.len() as f32 / now_.elapsed().as_millis() as f32;
        let pd = PartialDecryption {
            pd_ballots: decs,
            proofs,
        };
        let pd_h = hashing::hash(&pd);
        let ss = SignedStatement::pdecryptions(&cfg_h, &pd_h, contest, &self.keypair);
        let pd_path = self.work_cache.set_pdecryptions(&action, pd, &ss)?;
        board.add_decryption(&pd_path, contest, self_index)?;

        info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);

        Ok(())
    }

    pub(crate) fn combine_decryptions<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        decryptions_hs: Hashes,
        mix_h: Hash,
        share_hs: Hashes,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;
        info!(
            ">> Action: Combining decryptions (contest=[{}], self=[{}])..",
            contest, self_index
        );
        let now_ = std::time::Instant::now();
        let d_hs = clear_zeroes(&decryptions_hs);
        let s_hs = clear_zeroes(&share_hs);
        let pls = self
            .get_plaintexts(board, contest, d_hs, mix_h, s_hs, &cfg)
            .ok_or_else(|| TrusteeError::Msg("Could not build plaintexts".to_string()))?;

        let rate = pls.len() as f32 / now_.elapsed().as_millis() as f32;
        let plaintexts = Plaintexts { plaintexts: pls };
        let p_h = hashing::hash(&plaintexts);
        let ss = SignedStatement::plaintexts(&cfg_h, &p_h, contest, &self.keypair);
        let p_path = self.work_cache.set_plaintexts(&action, plaintexts, &ss)?;
        board.set_plaintexts(&p_path, contest)?;

        info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);

        Ok(())
    }

    pub(crate) fn check_plaintexts<B: BulletinBoard<E, G>>(
        &self,
        action: Act,
        self_index: u32,
        cfg_h: Hash,
        contest: u32,
        plaintexts_h: Hash,
        decryptions_hs: Hashes,
        mix_h: Hash,
        share_hs: Hashes,
        board: &mut B,
    ) -> Result<(), TrusteeError> {
        let cfg = board
            .get_config(cfg_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find cfg".to_string()))?;
        info!(
            ">> Action: Checking plaintexts (contest=[{}], self=[{}])",
            contest, self_index
        );
        let now_ = std::time::Instant::now();
        let s_hs = clear_zeroes(&share_hs);
        let d_hs = clear_zeroes(&decryptions_hs);
        let pls = self
            .get_plaintexts(board, contest, d_hs, mix_h, s_hs, &cfg)
            .ok_or_else(|| TrusteeError::Msg("Could not build plaintexts".to_string()))?;
        let rate = pls.len() as f32 / now_.elapsed().as_millis() as f32;
        let pls_board = board
            .get_plaintexts(contest, plaintexts_h)?
            .ok_or_else(|| TrusteeError::Msg("Could not find plaintexts".to_string()))?;
        assert!(pls == pls_board.plaintexts);

        let ss = SignedStatement::plaintexts(&cfg_h, &plaintexts_h, contest, &self.keypair);
        let p_path = self.work_cache.set_plaintexts_stmt(&action, &ss)?;
        board.set_plaintexts_stmt(&p_path, contest, self_index)?;
        info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);

        Ok(())
    }
}

fn clear_zeroes(input: &[[u8; 64]; crate::protocol::MAX_TRUSTEES]) -> Vec<[u8; 64]> {
    input.iter().cloned().filter(|&a| a != [0u8; 64]).collect()
}
