use clingo::*;
use crate::protocol::logic::*;
use crate::crypto::hashing::Hash;

use std::env;

#[derive(ToSymbol)]
struct Guilty(Person);

#[derive(ToSymbol)]
enum Person {
    Bob,
    Harry
}

#[derive(ToSymbol)]
struct Hsh(u32, String);

use base64::encode;

fn symbol_from_hash(hash: Hash) -> Result<clingo::Symbol, clingo::ClingoError> {
    Symbol::create_string(&encode(hash))
}

impl ToSymbol for ConfigPresent {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
        
        Symbol::create_function("config_present", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                self.2.symbol()?,
                self.3.symbol()?
            ],
        true)
    }
}

impl ToSymbol for ConfigSignedBy {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("config_signed_by", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?
            ],
        true)
    }
}

impl ToSymbol for PkShareSignedBy {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("pk_share_signed_by", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                symbol_from_hash(self.2)?,
                self.3.symbol()?
            ],
        true)
    }
}

impl ToSymbol for PkSignedBy {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("pk_signed_by", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                symbol_from_hash(self.2)?,
                self.3.symbol()?
            ],
        true)
    }
}

impl ToSymbol for BallotsSigned {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("ballots_signed", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                symbol_from_hash(self.2)?
            ],
        true)
    }
}

impl ToSymbol for MixSignedBy {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("mix_signed_by", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                symbol_from_hash(self.2)?,
                symbol_from_hash(self.3)?,
                self.4.symbol()?,
                self.5.symbol()?
            ],
        true)
    }
}

impl ToSymbol for DecryptionSignedBy {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("decryption_signed_by", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                symbol_from_hash(self.2)?,
                self.3.symbol()?
            ],
        true)
    }
}

impl ToSymbol for PlaintextsSignedBy {
    fn symbol(&self) -> Result<clingo::Symbol, clingo::ClingoError> {
    
        Symbol::create_function("plaintexts_signed_by", 
            &[
                symbol_from_hash(self.0)?,
                self.1.symbol()?,
                symbol_from_hash(self.2)?,
                self.3.symbol()?
            ],
        true)
    }
}

fn print_model(model: &Model, label: &str, show: ShowType) {
    print!("{}:", label);

    // retrieve the symbols in the model
    let atoms = model
        .symbols(show)
        .expect("Failed to retrieve symbols in the model.");

    for atom in atoms {
        // retrieve and print the symbol's string
        print!(" {}", atom.to_string().unwrap());
    }
    println!();
}

fn parse_model(model: &Model) {
    let atoms = model
        .symbols(ShowType::ATOMS)
        .expect("Failed to retrieve symbols in the model.");

    for atom in atoms {
        // retrieve and print the symbol's string
        // print!(" {}", atom.to_string().unwrap());
        let name = atom.name().unwrap();
        println!("{}", name);

        match name {
            "valp" => println!("valppppp"),
            _ => (),
        };
    }
    
}

fn solve(ctl: &mut Control) {
    // get a solve handle
    let mut handle = ctl
        .solve(SolveMode::YIELD, &[])
        .expect("Failed retrieving solve handle.");

    let result = handle.get().expect("Failed get on solve handle.");
    let unsat = result.intersects(SolveResult::UNSATISFIABLE);

    if unsat {
        println!("Unsatisfiable");
    }
    else {

        // loop over all models
        loop {
            match handle.model() {
                Ok(Some(model)) => {
                    // get model type
                    let model_type = model.model_type().unwrap();

                    // get running number of model
                    let number = model.number().unwrap();

                    print_model(model, "  shown", ShowType::SHOWN);
                    print_model(model, "  atoms", ShowType::ATOMS);
                }
                Ok(None) => {
                    // stop if there are no more models
                    break;
                }
                Err(e) => {
                    panic!("Error: {}", e);
                }
            }
            handle.resume().expect("Failed resume on solve handle.");
        }
    }

    // close the solve handle
    handle.close().expect("Failed to close solve handle.");
}

use clingo::{ExternalError, ExternalFunctionHandler};

struct Concat {}
impl ExternalFunctionHandler for Concat {
    fn on_external_function(
        &mut self,
        _location: &Location,
        name: &str,
        arguments: &[Symbol],
    ) -> Result<Vec<Symbol>,ExternalError> {
        if name == "concat" && arguments.len() == 2 {

            let value1 = arguments[0].string().unwrap();
            let value2 = arguments[1].string().unwrap();
            let result = format!("{},{}", value1, value2);

            let symbol = Symbol::create_string(&result).unwrap();
            Ok(vec![symbol])
        } else {            
            Err(ExternalError{ msg: "passed arguments "})?
        }
    }
}

#[cfg(test)]
mod tests {

    use clingo::*;
    use std::env;
    use crate::protocol::clingo::*;
    use clingo::FactBase;

    #[test]
    fn test_clingo() {
        // let options = env::args().skip(1).collect();

        // create a control object and pass command line arguments
        let mut ctl = Control::new(vec![]).expect("Failed creating clingo_control.");

        let program = r#"
        motive(harry).
        motive(sally).
        guilty(harry).
        motive(bob).
        
        valp(N + 1, @concat(H, H2)) :- hsh(N + 1, H), hsh(N, H2).

        :- valp(2, X).
        
        innocent(Suspect) :- motive(Suspect), not guilty(Suspect).
        #show valp/2.
        "#;

        ctl.add("base", &[], program).expect("Failed to add a logic program.");

        // ground the base part
        let part = Part::new("base", &[]).unwrap();
        let parts = vec![part];
        let p = Guilty(Person::Bob);
        let mut fb = FactBase::new();
        fb.insert(&p);
        fb.insert(&Hsh(1, String::from("hohoo")));
        fb.insert(&Hsh(2, String::from("hohoo")));
        fb.insert(&ConfigPresent([0u8;64], 1, 2, 3));
        ctl.add_facts(&fb);

        let mut concat = Concat{};
        ctl.ground_with_event_handler(&parts, &mut concat)
            .expect("Failed to ground a logic program.");

        // solve
        solve(&mut ctl);
    }
}


/*
fn main() {
    let bases = vec![2, 3, 5, 2];
    let values = vec![1, 2, 4, 1];
    
    let mut res = 0;
    for i in 0..bases.len() {
        res = res * bases[i] + values[i];
    }
    println!("{} {}", res, (2 * 3 * 5 * 2));
    
    let mut v = vec![];
    
    for i in (0..bases.len()).rev() {
        // print!(" {}", (res % bases[i]));
        v.push(res % bases[i]);
        res = res / bases[i];
    }
    v.reverse();
    println!("{:?}", v);
}
*/