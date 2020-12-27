use std::fmt;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::convert::TryInto;
use std::fmt::Debug;

use serde::de::DeserializeOwned;
use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::Verifier;
use crepe::crepe;
use log::info;

use crate::hashing;
use crate::hashing::*;
use crate::statement::*;
use crate::bb::*;
use crate::util;
use crate::arithm::Element;
use crate::group::Group;
use crate::action::Act;
use crate::util::short;
use crate::trustee::Trustee;

pub type TrusteeTotal = u32;
pub type TrusteeIndex = u32;
pub type ContestIndex = u32;
pub type ConfigHash = Hash;
pub type ShareHash = Hash;
pub type PkHash = Hash;
pub type BallotsHash = Hash;
pub type MixHash = Hash;
pub type DecryptionHash = Hash;
pub type PlaintextsHash = Hash;
pub type Hashes = [Hash; 10];

type OutputF = (HashSet<Do>, HashSet<ConfigOk>, HashSet<PkSharesAll>, HashSet<PkOk>, 
    HashSet<PkSharesUpTo>, HashSet<ConfigSignedUpTo>, HashSet<Contest>,
    HashSet<PkSignedUpTo>, HashSet<MixSignedUpTo>, HashSet<MixOk>, HashSet<ContestMixedUpTo>,
    HashSet<ContestMixedOk>, HashSet<DecryptionsUpTo>, HashSet<DecryptionsAll>,
    HashSet<PlaintextsSignedUpTo>, HashSet<PlaintextsOk>);

#[derive(Debug)]
pub struct SVerifier {
    pub statement: SignedStatement,
    pub trustee: i32,
    pub contest: u32
}

impl SVerifier {
    
    fn verify<E: Element, G: Group<E>, B: BulletinBoard<E, G>>(&self, board: &B) -> Option<InputFact> {
        let statement = &self.statement.statement;
        let config = board.get_config_unsafe()?;
        
        let (pk, self_t): (SPublicKey, u32) =
        if self.trustee >= 0 {
            (config.trustees[self.trustee as usize], self.trustee.try_into().unwrap())
        } else {
            (config.ballotbox, 0)
        };
        
        let statement_hash = hashing::hash(statement);
        let verified = pk.verify(&statement_hash, &self.statement.signature);
        let config_h = util::to_u8_64(&statement.hashes[0]);
        // info!("* Verify returns: [{}] on [{:?}] from trustee [{}] for contest [{}]", verified.is_ok(), 
        //    &self.statement.statement.stype, &self.trustee, &self.contest
        //);
        
        let mixer_t = statement.trustee_aux.unwrap_or(self_t);

        match statement.stype {
            StatementType::Config => {
                self.ret(
                    InputFact::config_signed_by(config_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::share_signed_by(config_h, self.contest, share_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::pk_signed_by(config_h, self.contest, pk_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::Ballots => {
                let ballots_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::ballots_signed(config_h, self.contest, ballots_h),
                    verified.is_ok()
                )
            },
            StatementType::Mix => {
                let mix_h = util::to_u8_64(&statement.hashes[1]);
                let ballots_h = util::to_u8_64(&statement.hashes[2]);
                self.ret(
                    InputFact::mix_signed_by(config_h, self.contest, mix_h, ballots_h, mixer_t, self_t),
                    verified.is_ok()
                )

            },
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::decryption_signed_by(config_h, self.contest, pdecryptions_h, self_t),
                    verified.is_ok()
                )

            },
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::plaintexts_signed_by(config_h, self.contest, plaintexts_h, self_t),
                    verified.is_ok()
                )
            }
        }
    }

    fn ret(&self, fact: InputFact, verified: bool) -> Option<InputFact> {
        if verified {
            Some(fact)
        } else {
            None
        }
    }
}

use strum::Display;

#[derive(Copy, Clone, Display)]
enum InputFact {
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
    fn config_present(c: ConfigHash, cn: ContestIndex, trustees: TrusteeIndex, 
        self_index: TrusteeIndex) -> InputFact {
        
        InputFact::ConfigPresent(ConfigPresent(c, cn, trustees, self_index))
    }
    fn config_signed_by(c: ConfigHash, trustee: TrusteeIndex) -> InputFact {
        InputFact::ConfigSignedBy(ConfigSignedBy(c, trustee))
    }
    fn share_signed_by(c: ConfigHash, contest: ContestIndex, share: ShareHash,
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PkShareSignedBy(PkShareSignedBy(c, contest, share, trustee))
    }
    fn pk_signed_by(c: ConfigHash, contest: ContestIndex, pk: PkHash, 
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::PkSignedBy(PkSignedBy(c, contest, pk, trustee))
    }
    fn ballots_signed(c: ConfigHash, contest: ContestIndex, 
        ballots: BallotsHash) -> InputFact {
        
        InputFact::BallotsSigned(BallotsSigned(c, contest, ballots))
    }
    fn mix_signed_by(c: ConfigHash, contest: ContestIndex, mix: MixHash, ballots: BallotsHash,
        mixer_t: TrusteeIndex, signer_t: TrusteeIndex) -> InputFact {
        
        InputFact::MixSignedBy(MixSignedBy(c, contest, mix, ballots, mixer_t, signer_t))
    }
    fn decryption_signed_by(c: ConfigHash, contest: ContestIndex, decryption: DecryptionHash, 
        trustee: TrusteeIndex) -> InputFact {
        
        InputFact::DecryptionSignedBy(DecryptionSignedBy(c, contest, decryption, trustee))
    }
    fn plaintexts_signed_by(c: ConfigHash, contest: ContestIndex, plaintexts: PlaintextsHash,
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

fn load_facts(facts: &Vec<InputFact>, runtime: &mut Crepe) {
    let mut sorted = facts.to_vec();
    sorted.sort_by(|a, b| {
        a.to_string().partial_cmp(&b.to_string()).unwrap()
    });
    sorted.into_iter().map(|f| {
    // facts.into_iter().map(|f| {
        info!("IFact {:?}", f);
        match f {
            InputFact::ConfigPresent(x) => runtime.extend(&[x]),
            InputFact::ConfigSignedBy(x) => runtime.extend(&[x]),
            InputFact::PkShareSignedBy(x) => runtime.extend(&[x]),
            InputFact::PkSignedBy(x) => runtime.extend(&[x]),
            InputFact::BallotsSigned(x) => runtime.extend(&[x]),
            InputFact::MixSignedBy(x) => runtime.extend(&[x]),
            InputFact::DecryptionSignedBy(x) => runtime.extend(&[x]),
            InputFact::PlaintextsSignedBy(x) => runtime.extend(&[x])
        }
    }).count();
    info!("\n");
}

pub struct Facts {
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

impl Facts {
    fn new(input_facts: Vec<InputFact>, f: OutputF) -> Facts {
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

        Facts{
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

    fn log(&self) {
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
        if let InputFact::ConfigPresent(ConfigPresent(_, _, _, self_t)) = self.get_cp() {
            Some(self_t)
        }
        else {
            None
        }
    }
    pub fn get_trustee_count(&self) -> Option<u32> {
        if let InputFact::ConfigPresent(ConfigPresent(_, _, trustees, _)) = self.get_cp() {
            Some(trustees)
        }
        else {
            None
        }
    }
    fn get_cp(&self) -> InputFact {
        self.input_facts[self.input_facts.len() - 1]
    }
}

crepe! {
    @input
    struct ConfigPresent(ConfigHash, ContestIndex, TrusteeIndex, TrusteeIndex);
    @input
    struct ConfigSignedBy(ConfigHash, u32);
    @input
    struct PkShareSignedBy(ConfigHash, ContestIndex, ShareHash, TrusteeIndex);
    @input
    struct PkSignedBy(ConfigHash, ContestIndex, PkHash, TrusteeIndex);
    @input
    struct BallotsSigned(ConfigHash, ContestIndex, BallotsHash);
    @input
    struct MixSignedBy(ConfigHash, ContestIndex, MixHash, BallotsHash, TrusteeIndex, TrusteeIndex);
    @input
    struct DecryptionSignedBy(ConfigHash, ContestIndex, DecryptionHash, TrusteeIndex);
    @input
    struct PlaintextsSignedBy(ConfigHash, ContestIndex, PlaintextsHash, TrusteeIndex);

    // 0
    @output
    struct Do(Act);
    // 1
    @output
    struct ConfigOk(ConfigHash);
    // 2
    @output
    struct PkSharesAll(ConfigHash, ContestIndex, Hashes);
    // 3
    @output
    struct PkOk(ConfigHash, ContestIndex, PkHash);
    // 4
    @output
    struct PkSharesUpTo(ConfigHash, ContestIndex, TrusteeIndex, Hashes);
    // 5
    @output
    struct ConfigSignedUpTo(ConfigHash, TrusteeIndex);
    // 6
    @output
    struct Contest(ConfigHash, ContestIndex);
    // 7
    @output
    struct PkSignedUpTo(ConfigHash, ContestIndex, PkHash, TrusteeIndex);
    // 8
    @output
    struct MixSignedUpTo(ConfigHash, ContestIndex, MixHash, BallotsHash, TrusteeIndex);
    // 9
    @output
    struct MixOk(ConfigHash, ContestIndex, MixHash, BallotsHash);
    // 10
    @output
    struct ContestMixedUpTo(ConfigHash, ContestIndex, MixHash, TrusteeIndex);
    // 11
    @output
    struct ContestMixedOk(ConfigHash, ContestIndex, MixHash);
    // 11
    @output
    struct DecryptionsUpTo(ConfigHash, ContestIndex, TrusteeIndex, Hashes);
    // 12
    @output
    struct DecryptionsAll(ConfigHash, ContestIndex, Hashes);
    // 13
    @output
    struct PlaintextsSignedUpTo(ConfigHash, ContestIndex, PlaintextsHash, TrusteeIndex);
    // 14
    @output
    struct PlaintextsOk(ConfigHash, ContestIndex, PlaintextsHash);
    
    Do(Act::CheckConfig(config)) <- 
        ConfigPresent(config, _, _, self_t),
        !ConfigSignedBy(config, self_t);
    
    Do(Act::PostShare(config, contest)) <- 
        ConfigPresent(config, _, _, self_t),
        Contest(config, contest),
        ConfigOk(config),
        !PkShareSignedBy(config, contest, _, self_t);
    
    Do(Act::CombineShares(config, contest, hashes)) <- 
        PkSharesAll(config, contest, hashes),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        !PkSignedBy(config, contest, _, 0);

    Do(Act::CheckPk(config, contest, pk_hash, hashes)) <- 
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        PkSharesAll(config, contest, hashes),
        PkSignedBy(config, contest, pk_hash, 0),
        !PkSignedBy(config, contest, pk_hash, self_t);

    // mix 0
    Do(Act::Mix(config, contest, ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),    
        BallotsSigned(config, contest, ballots_hash),
        !MixSignedBy(config, contest, _, _, 0, 0);

    // mix n
    Do(Act::Mix(config, contest, mix_ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        (self_t > 0),
        MixSignedBy(config, contest, mix_ballots_hash, _, self_t - 1, self_t - 1),
        MixSignedBy(config, contest, mix_ballots_hash, _, self_t - 1, self_t),
        !MixSignedBy(config, contest, _, _, self_t, self_t);
  
    // check mix 0
    Do(Act::CheckMix(config, contest, 0, mix_hash, ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),    
        MixSignedBy(config, contest, mix_hash, ballots_hash, 0, 0),
        // input ballots to mix came from the ballotbox
        BallotsSigned(config, contest, ballots_hash),
        !MixSignedBy(config, contest, mix_hash, ballots_hash, 0, self_t);

    // check mix n
    Do(Act::CheckMix(config, contest, mixer_t, mix_hash, mix_ballots_hash, pk_hash)) <- 
        PkOk(config, contest, pk_hash),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),    
        MixSignedBy(config, contest, mix_hash, mix_ballots_hash, mixer_t, _signer_t),
        (mixer_t > 0),
        // input ballots to mix came from a previous mix, thus (mixer_t - 1)
        MixSignedBy(config, contest, mix_ballots_hash, _, mixer_t - 1, _),
        !MixSignedBy(config, contest, mix_hash, mix_ballots_hash, mixer_t, self_t);
    
    Do(Act::PartialDecrypt(config, contest, mix_hash, share)) <- 
        PkOk(config, contest, _pk_hash),
        ConfigPresent(config, _n_trustees, _, self_t),
        ConfigOk(config),
        PkShareSignedBy(config, contest, share, self_t),
        ContestMixedOk(config, contest, mix_hash),
        !DecryptionSignedBy(config, contest, _, self_t);

    Do(Act::CombineDecryptions(config, contest, decryptions, mix_hash, shares)) <- 
        DecryptionsAll(config, contest, decryptions),
        ConfigPresent(config, _, _, 0),
        ConfigOk(config),
        ContestMixedOk(config, contest, mix_hash),
        PkSharesAll(config, contest, shares),
        !PlaintextsSignedBy(config, contest, _, 0);

    Do(Act::CheckPlaintexts(config, contest, plaintext_hash, decryptions, mix_hash, shares)) <- 
        DecryptionsAll(config, contest, decryptions),
        ConfigPresent(config, _, _, self_t),
        ConfigOk(config),
        ContestMixedOk(config, contest, mix_hash),
        PkSharesAll(config, contest, shares),
        PlaintextsSignedBy(config, contest, plaintext_hash, 0),
        !PlaintextsSignedBy(config, contest, plaintext_hash, self_t);

    PlaintextsSignedUpTo(config, contest, plaintext_hash, 0) <-
        PlaintextsSignedBy(config, contest, plaintext_hash, 0);

    PlaintextsSignedUpTo(config, contest, plaintext_hash, trustee + 1) <-
        PlaintextsSignedUpTo(config, contest, plaintext_hash, trustee),   
        PlaintextsSignedBy(config, contest, plaintext_hash, trustee + 1);

    PlaintextsOk(config, contest, plaintext_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PlaintextsSignedUpTo(config, contest, plaintext_hash, total_t - 1);

    DecryptionsUpTo(config, contest, 0, first) <-
        DecryptionSignedBy(config, contest, decryption, 0),
        let first = array_make(decryption);

    DecryptionsUpTo(config, contest, trustee + 1, decryptions) <- 
        DecryptionsUpTo(config, contest, trustee, input_decryptions),
        DecryptionSignedBy(config, contest, decryption, trustee + 1),
        let decryptions = array_set(input_decryptions, trustee + 1, decryption);

    DecryptionsAll(config, contest, decryptions) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        DecryptionsUpTo(config, contest, total_t - 1, decryptions);
    
    MixSignedUpTo(config, contest, mix_hash, ballots_hash, 0) <-
        MixSignedBy(config, contest, mix_hash, ballots_hash, _, 0);

    MixSignedUpTo(config, contest, mix_hash, ballots_hash, signer_t + 1) <-
        MixSignedUpTo(config, contest, mix_hash, ballots_hash, signer_t),
        MixSignedBy(config, contest, mix_hash, ballots_hash, _mixer_t, signer_t + 1);

    MixOk(config, contest, mix_hash, ballots_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        MixSignedUpTo(config, contest, mix_hash, ballots_hash, total_t - 1);

    ContestMixedUpTo(config, contest, mix_hash, 0) <- 
        MixOk(config, contest, mix_hash, ballots_hash),
        BallotsSigned(config, contest, ballots_hash);

    ContestMixedUpTo(config, contest, mix_hash, trustee + 1) <- 
        ContestMixedUpTo(config, contest, previous_mix_hash, trustee),
        MixOk(config, contest, mix_hash, previous_mix_hash);

    ContestMixedOk(config, contest, mix_hash) <- 
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        ContestMixedUpTo(config, contest, mix_hash, total_t - 1);
    
    ConfigSignedUpTo(config, 0) <-
        ConfigSignedBy(config, 0);
    
    ConfigSignedUpTo(config, trustee + 1) <- 
        ConfigSignedUpTo(config, trustee),
        ConfigSignedBy(config, trustee + 1);
    
    ConfigOk(config) <- 
        ConfigPresent(config, _, total_t, _),
        ConfigSignedUpTo(config, total_t - 1);
    
    PkSharesUpTo(config, contest, 0, first) <-
        PkShareSignedBy(config, contest, share, 0),
        let first = array_make(share);

    PkSharesUpTo(config, contest, trustee + 1, shares) <- 
        PkSharesUpTo(config, contest, trustee, input_shares),
        PkShareSignedBy(config, contest, share, trustee + 1),
        let shares = array_set(input_shares, trustee + 1, share);

    PkSharesAll(config, contest, shares) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PkSharesUpTo(config, contest, total_t - 1, shares);

    PkOk(config, contest, pk_hash) <-
        ConfigPresent(config, _, total_t, _),
        ConfigOk(config),
        PkSignedUpTo(config, contest, pk_hash, total_t - 1);
    
    PkSignedUpTo(config, contest, pk_hash, 0) <-
        PkSignedBy(config, contest, pk_hash, 0);

    PkSignedUpTo(config, contest, pk_hash, trustee + 1) <-
        PkSignedUpTo(config, contest, pk_hash, trustee),
        PkSignedBy(config, contest, pk_hash, trustee + 1);

    Contest(config, contests - 1) <-
        ConfigPresent(config, contests, _, _self);

    Contest(config, n - 1) <- Contest(config, n),
        (n > 0);
}

fn array_make(value: Hash) -> Hashes {
    let mut ret = [[0u8; 64]; 10];
    ret[0] = value;

    ret
}

fn array_set(mut input: Hashes, index: u32, value: Hash) -> Hashes {
    input[index as usize] = value;

    input
}

pub struct Protocol <E, G, B> {
    trustee: Trustee<E, G>,
    phantom_b: PhantomData<B>
}

impl<E: Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned,
    B: BulletinBoard<E, G>> Protocol<E, G, B> {

    pub fn new(trustee: Trustee<E, G>) -> Protocol<E, G, B> {
        Protocol {
            trustee,
            phantom_b: PhantomData
        }
    }
    
    fn get_facts(&self, board: &B) -> Vec<InputFact> {
    
        let self_pk = self.trustee.keypair.public;
        let now = std::time::Instant::now();
        let svs = board.get_statements();
        // info!("SVerifiers: {}", svs.len());
        let mut facts: Vec<InputFact> = svs.iter()
            .map(|sv| sv.verify(board))
            .filter(|f| f.is_some())
            .map(|f| f.unwrap())
            .collect();
        
        if let Some(cfg) = board.get_config_unsafe() {
            let trustees = cfg.trustees.len();
            
            let self_pos = cfg.trustees.iter()
                .position(|s| s.to_bytes() == self_pk.to_bytes())
                .unwrap();
            let hash = hashing::hash(&cfg);
            let contests = cfg.contests;

            let f = InputFact::config_present(
                hash,
                contests,
                trustees as u32,
                self_pos as u32
            );
            facts.push(f);
        };
        info!("Input facts derived in [{}ms]", now.elapsed().as_millis());
        info!("");
        facts
    }
    
    pub fn process_facts(&self, board: &B) -> Facts {
        let mut runtime = Crepe::new();
        let input_facts = self.get_facts(board);
        load_facts(&input_facts, &mut runtime);
        
        let now = std::time::Instant::now();
        let output = runtime.run();
        let done = now.elapsed().as_millis();
        let actions = output.0.len();
        
        let ret = Facts::new(input_facts, output);
    
        ret.log();
        info!("");
        info!("Output facts ({} actions) derived in [{}ms]", actions, done);
        
        ret
    }

    pub fn run(&self, facts: Facts, board: &mut B) -> u32 {
        self.trustee.run(facts, board)
    }

    pub fn step(&self, board: &mut B) -> u32 {
        let output = self.process_facts(&board);

        self.trustee.run(output, board)
    }
}