use clingo::*;
use std::env;

#[derive(ToSymbol)]
struct Guilty(Person);

#[derive(ToSymbol)]
enum Person {
    Bob,
    Harry
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

fn solve(ctl: &mut Control) {
    // get a solve handle
    let mut handle = ctl
        .solve(SolveMode::YIELD, &[])
        .expect("Failed retrieving solve handle.");

    // loop over all models
    loop {
        handle.resume().expect("Failed resume on solve handle.");
        match handle.model() {
            Ok(Some(model)) => {
                // get model type
                let model_type = model.model_type().unwrap();

                let type_string = match model_type {
                    ModelType::StableModel => "Stable model",
                    ModelType::BraveConsequences => "Brave consequences",
                    ModelType::CautiousConsequences => "Cautious consequences",
                };

                // get running number of model
                let number = model.number().unwrap();

                println!("{}: {}", type_string, number);

                print_model(model, "  shown", ShowType::SHOWN);
                print_model(model, "  atoms", ShowType::ATOMS);
                print_model(model, "  terms", ShowType::TERMS);
                // print_model(model, " ~atoms", ShowType::COMPLEMENT | ShowType::ATOMS);
            }
            Ok(None) => {
                // stop if there are no more models
                break;
            }
            Err(e) => {
                panic!("Error: {}", e);
            }
        }
    }

    // close the solve handle
    handle.close().expect("Failed to close solve handle.");
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

        let program = "
        motive(harry).
        motive(sally).
        guilty(harry).
        motive(bob).
        
        
        
        innocent(Suspect) :- motive(Suspect), not guilty(Suspect).
        #show innocent/1.
        ";

        ctl.add("base", &[], program).expect("Failed to add a logic program.");

        // ground the base part
        let part = Part::new("base", &[]).unwrap();
        let parts = vec![part];
        // let p = Motive("bob".to_string());
        let p = Guilty(Person::Bob);
        let mut fb = FactBase::new();
        fb.insert(&p);
        ctl.add_facts(&fb);

        ctl.ground(&parts)
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