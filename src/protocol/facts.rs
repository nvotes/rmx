use std::fmt;
use std::collections::HashSet;
use log::info;

use strum::Display;

use crate::util::{short, shortm};
use crate::protocol::logic::*;

#[derive(Copy, Clone, Display)]
pub(super) enum InputFact {
    ConfigPresent(ConfigPresent),
    ConfigSignedBy(ConfigSignedBy),
    PkShareSignedBy(PkShareSignedBy),
    PkSignedBy(PkSignedBy),
    BallotsSigned(BallotsSigned),
    MixSignedBy(MixSignedBy),
    DecryptionSignedBy(DecryptionSignedBy),
    PlaintextsSignedBy(PlaintextsSignedBy)
}
impl InputFact {
    pub(super) fn config_present(c: ConfigHash, cn: ContestIndex, trustees: TrusteeIndex, 
        self_index: TrusteeIndex) -> InputFact {
        
        InputFact::ConfigPresent(ConfigPresent(c, cn, trustees, self_index))
    }
    pub(super) fn config_signed_by(c: ConfigHash, trustee: TrusteeIndex) -> InputFact {
        InputFact::ConfigSignedBy(ConfigSignedBy(c, trustee))
    }
    pub(super) fn share_signed_by(c: ConfigHash, contest: ContestIndex, share: ShareHash,
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PkShareSignedBy(PkShareSignedBy(c, contest, share, trustee))
    }
    pub(super) fn pk_signed_by(c: ConfigHash, contest: ContestIndex, pk: PkHash, 
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PkSignedBy(PkSignedBy(c, contest, pk, trustee))
    }
    pub(super) fn ballots_signed(c: ConfigHash, contest: ContestIndex, 
        ballots: BallotsHash) -> InputFact {
        
        InputFact::BallotsSigned(BallotsSigned(c, contest, ballots))
    }
    pub(super) fn mix_signed_by(c: ConfigHash, contest: ContestIndex, mix: MixHash, ballots: BallotsHash,
        mixer_t: TrusteeIndex, signer_t: TrusteeIndex) -> InputFact {
        
        InputFact::MixSignedBy(MixSignedBy(c, contest, mix, ballots, mixer_t, signer_t))
    }
    pub(super) fn decryption_signed_by(c: ConfigHash, contest: ContestIndex, decryption: DecryptionHash, 
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::DecryptionSignedBy(DecryptionSignedBy(c, contest, decryption, trustee))
    }
    pub(super) fn plaintexts_signed_by(c: ConfigHash, contest: ContestIndex, plaintexts: PlaintextsHash,
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PlaintextsSignedBy(
            PlaintextsSignedBy(c, contest, plaintexts, trustee)
        )
    }
}

impl fmt::Debug for InputFact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputFact::ConfigPresent(x) => write!(f, 
                "ConfigPresent: [contests={} trustees={} self={}] {:?}", 
                x.1, x.2, x.3, short(&x.0)),
            InputFact::ConfigSignedBy(x) => write!(f, 
                "ConfigSignedBy: [{}] cfg: {:?}", 
                x.1, short(&x.0)),
            InputFact::PkShareSignedBy(x) => write!(f, 
                "PkShareSignedBy [cn={} tr={}] share: {:?}", 
                x.1, x.3, short(&x.2)),
            InputFact::PkSignedBy(x) => write!(f, 
                "PkSignedBy [cn={} tr={}] for pk: {:?}", 
                x.1, x.3, short(&x.2)),
            
            InputFact::BallotsSigned(x) => write!(f, 
                "BallotsSigned [cn={}] [ballots={:?}]", x.1, short(&x.2)),
            InputFact::MixSignedBy(x) => write!(f, 
                "MixSignedBy [cn={}] {:?} <- {:?}, [mxr={}, signer={}]", 
                x.1, short(&x.2), short(&x.3), x.4, x.5),
            InputFact::DecryptionSignedBy(x) => write!(f, 
                "DecryptionSignedBy [cn={}] [signer={}] {:?}", 
                x.1, x.3, short(&x.0)),
            InputFact::PlaintextsSignedBy(x) => write!(f, 
                "PlaintextsSignedBy [cn={}] {:?}", 
                x.1, short(&x.0))
        }
    }
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum Act {
    CheckConfig(ConfigHash),
    PostShare(ConfigHash, ContestIndex),
    CombineShares(ConfigHash, ContestIndex, Hashes),
    CheckPk(ConfigHash, ContestIndex, PkHash, Hashes),
    Mix(ConfigHash, ContestIndex, BallotsHash, PkHash),
    CheckMix(ConfigHash, ContestIndex, TrusteeIndex, MixHash, BallotsHash, PkHash),
    PartialDecrypt(ConfigHash, ContestIndex, BallotsHash, ShareHash),
    CombineDecryptions(ConfigHash, ContestIndex, Hashes, MixHash, Hashes),
    CheckPlaintexts(ConfigHash, ContestIndex, PlaintextsHash, Hashes, MixHash, Hashes)
}

impl fmt::Debug for Act {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Act::CheckConfig(cfg) => write!(f, "CheckConfig {:?}", short(cfg)),
            Act::PostShare(cfg, cnt) => write!(f, "PostShare cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CombineShares(_cfg, cnt, hs) => write!(f, "CombineShares cn=[{}] shares: {:?}", cnt, shortm(hs)),
            Act::CheckPk(_cfg, cnt, h1, hs) => write!(f, "CheckPk cn=[{}], pk {:?} shares: {:?}", cnt, short(h1), shortm(hs)),
            Act::Mix(cfg, cnt, _bh, _pk_h) => write!(f, "Mix cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CheckMix(_cfg, cnt, t, mh, _bh, _pk_h) => write!(f, "CheckMix cn=[{}] mix={:?} posted by tr=[{}]", cnt, short(mh), t),
            Act::PartialDecrypt(cfg, cnt, _h1, _share_h) => write!(f, "PartialDecrypt cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CombineDecryptions(cfg, cnt, _hs, _mix_h, _share_hs) => write!(f, "CombineDecryptions cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CheckPlaintexts(cfg, cnt, _p_h, _d_hs, _mix_h, _share_hs) => write!(f, "CheckPlaintexts cn=[{}] cfg: {:?}", cnt, short(cfg))
        }
    }
}

type DatalogOutput = (HashSet<Do>, HashSet<ConfigOk>, HashSet<PkSharesAll>, HashSet<PkOk>, 
    HashSet<PkSharesUpTo>, HashSet<ConfigSignedUpTo>, HashSet<Contest>,
    HashSet<PkSignedUpTo>, HashSet<MixSignedUpTo>, HashSet<MixOk>, HashSet<ContestMixedUpTo>,
    HashSet<ContestMixedOk>, HashSet<DecryptionsUpTo>, HashSet<DecryptionsAll>,
    HashSet<PlaintextsSignedUpTo>, HashSet<PlaintextsOk>);

pub struct AllFacts {
    pub(self) input_facts: Vec<InputFact>,
    pub all_actions: Vec<Act>,
    pub check_config: Vec<Act>,
    pub post_share: Vec<Act>,
    pub combine_shares: Vec<Act>,
    pub check_pk: Vec<Act>,
    pub check_mix: Vec<Act>,
    pub mix: Vec<Act>,
    pub partial_decrypt: Vec<Act>,
    pub combine_decryptions: Vec<Act>,
    pub check_plaintexts: Vec<Act>,
    config_ok: HashSet<ConfigOk>,
    pk_shares_ok: HashSet<PkSharesAll>,
    pk_ok: HashSet<PkOk>,
    mixes_ok: HashSet<MixOk>,
    contest_mixed_ok: HashSet<ContestMixedOk>,
    decryptions_all: HashSet<DecryptionsAll>,
    plaintexts_ok: HashSet<PlaintextsOk>
}

impl AllFacts {
    pub(super) fn new(input_facts: Vec<InputFact>, f: DatalogOutput) -> AllFacts {
        let mut all_actions = vec![];
        let mut check_config = vec![];
        let mut post_share = vec![];
        let mut combine_shares = vec![];
        let mut check_pk = vec![];
        let mut check_mix = vec![];
        let mut mix = vec![];
        let mut partial_decrypt = vec![];
        let mut combine_decryptions = vec![];
        let mut check_plaintexts = vec![];
        
        let actions = f.0;
        for a in actions {
            match a.0 {
                Act::CheckConfig(..) => check_config.push(a.0),
                Act::PostShare(..) => post_share.push(a.0),
                Act::CombineShares(..) => combine_shares.push(a.0),
                Act::CheckPk(..) => check_pk.push(a.0),
                Act::CheckMix(..) => check_mix.push(a.0),
                Act::Mix(..) => mix.push(a.0),
                Act::PartialDecrypt(..) => partial_decrypt.push(a.0),
                Act::CombineDecryptions(..) => combine_decryptions.push(a.0),
                Act::CheckPlaintexts(..) => check_plaintexts.push(a.0)
            }  
            all_actions.push(a.0);
        }

        let config_ok = f.1;
        let pk_shares_ok = f.2;
        let pk_ok = f.3;
        let mixes_ok = f.9;
        let contest_mixed_ok = f.11;
        let decryptions_all = f.13;
        let plaintexts_ok = f.15;

        AllFacts {
            input_facts,
            all_actions,
            check_config,
            post_share,
            combine_shares,
            check_pk,
            check_mix,
            mix,
            partial_decrypt,
            combine_decryptions,
            check_plaintexts,
            config_ok,
            pk_shares_ok,
            pk_ok,
            mixes_ok,
            contest_mixed_ok,
            decryptions_all,
            plaintexts_ok
        }
    }

    pub(super) fn log(&self) {
        let next = &self.config_ok;
        for f in next {
            info!("OFact: ConfigOk {:?}", short(&f.0));
        }
        let next = &self.pk_shares_ok;
        for f in next {
            info!("OFact: PkSharesAll {:?}", short(&f.0));
        }
        let next = &self.pk_ok;
        for f in next {
            info!("OFact: PkOk {:?}", short(&f.0));
        }
        let next = &self.mixes_ok;
        for f in next {
            info!("OFact: MixOk cn=[{}] {:?} <- {:?}", 
            f.1, short(&f.2), short(&f.3));
        }
        let next = &self.contest_mixed_ok;
        for f in next {
            info!("OFact: ContestMixedOk cn=[{}] mix={:?} cfg {:?}", 
            f.1, short(&f.2), short(&f.0));
        }
        let next = &self.decryptions_all;
        for f in next {
            info!("OFact: DecryptionsAll cn=[{}] cfg {:?}", 
            f.1, short(&f.0));
        }
        let next = &self.plaintexts_ok;
        for f in next {
            info!("OFact: PlaintextsOk cn=[{}] cfg {:?}", 
            f.1, short(&f.0));
        }
        let next = &self.all_actions; 
        for f in next {
            info!("OFact: Action {:?}", f);
        }
    }

    pub fn pk_shares_len(&self) -> usize {
        self.pk_shares_ok.len()
    }
    pub fn pk_ok_len(&self) -> usize {
        self.pk_ok.len()
    }
    pub fn config_ok(&self) -> bool {
        self.config_ok.len() == 1
    }
    pub fn get_self_index(&self) -> Option<u32> {
        if let InputFact::ConfigPresent(ConfigPresent(_, _, _, self_t)) = self.get_config_present() {
            Some(self_t)
        }
        else {
            None
        }
    }
    pub fn get_trustee_count(&self) -> Option<u32> {
        if let InputFact::ConfigPresent(ConfigPresent(_, _, trustees, _)) = self.get_config_present() {
            Some(trustees)
        }
        else {
            None
        }
    }
    fn get_config_present(&self) -> InputFact {
        self.input_facts[self.input_facts.len() - 1]
    }
}