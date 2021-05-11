% https://marketplace.visualstudio.com/items?itemName=abelcour.asp-syntax-highlight
#script (python)

from clingo import String

def concat(a, b):
	return String(a.string + "," + b.string)

def concat2(a, b):
	return String(a.string + "-" + str(b.number))

#end.

#const auths = 2.
#const horizon = 8.
#const contests = 2.

% in execution mode, A and T will be zero: a(0), t(0)
t(0..horizon).
a(0..auths - 1).

% bootstrap protocol by adding config
% We're duplicating the A value so that each authority can select their particular
% configuration using that as an index, it just happens that the index
% is currently the only authority-specific information in the configuration
% In execution mode, A will be set to 0, so input fact parsing should
% include an extra 0 in the config predicate
posted_at(config(config_hash, contests, auths, A, A), -1, 0) :- a(A).
% once the pk is posted, simulate posting ballots by the ballotbox at T + 1
posted_at(ballots(ConfigHash, Contest, "ballots_hash"), -1, T + 1) :- 
	pk_ok(ConfigHash, Contest, PkHash, T),
	not posted_at(ballots(ConfigHash, Contest, _), -1, T).


%*******************************************************************************%

% action rules are shared with execution mode
% do() acts as a wrapper to include A and T information when modeling
do(act_sign_config(ConfigHash), A, T) :-
	posted(config(ConfigHash, _, _, SelfT, A), T),
	not posted(config_signature(ConfigHash, A), T),
	a(A).

do(act_post_share(ConfigHash, Contest), A, T) :-
    posted(config(ConfigHash, _, _, SelfT, A), T),
	contest(ConfigHash, Contest, T),
	config_ok(ConfigHash, T),
	not posted(pk_share(ConfigHash, Contest, _, SelfT), T),
	a(A).

do(act_combine_shares(ConfigHash, Contest, Hashes), A, T) :-
    posted(config(ConfigHash, _, _, 0, A), T),
	config_ok(ConfigHash, T),
	pk_shares_ok(ConfigHash, Contest, Hashes, T),
    not posted(pk_signature(ConfigHash, Contest, _, 0), T),
	a(A).

do(act_sign_pk(ConfigHash, Contest, PkHash, Hashes), A, T) :-
	posted(config(ConfigHash, _, _, SelfT, A), T),
	config_ok(ConfigHash, T),
	pk_shares_ok(ConfigHash, Contest, Hashes, T),
	posted(pk_signature(ConfigHash, Contest, PkHash, 0), T),
    not posted(pk_signature(ConfigHash, Contest, PkHash, SelfT), T),
	a(A).

do(act_mix(ConfigHash, Contest, BallotsHash, PkHash), A, T) :-
	pk_ok(ConfigHash, Contest, PkHash, T),
	posted(config(ConfigHash, _, _, 0, A), T),
	config_ok(ConfigHash, T),
	posted(ballots(ConfigHash, Contest, BallotsHash), T),
	not posted(mix_signature(ConfigHash, Contest, _, _, 0, 0), T),
	a(A).

do(act_mix(ConfigHash, Contest, MixHash, PkHash), A, T) :-
	pk_ok(ConfigHash, Contest, PkHash, T),
	posted(config(ConfigHash, _, _, SelfT, A), T),
	config_ok(ConfigHash, T),
	SelfT > 0,
	% the previous mix was signed by its producer
	posted(mix_signature(ConfigHash, Contest, MixHash, _, SelfT - 1, SelfT - 1), T),
	% we have verified the previous mix
	posted(mix_signature(ConfigHash, Contest, MixHash, _, SelfT - 1, SelfT), T),
	not posted(mix_signature(ConfigHash, Contest, _, _, SelfT, SelfT), T),
	a(A).

% check mix 0
do(act_check_mix(ConfigHash, Contest, 0, MixHash, BallotsHash, PkHash), A, T) :-
	pk_ok(ConfigHash, Contest, PkHash, T),
	posted(config(ConfigHash, _, _, SelfT, A), T),
	config_ok(ConfigHash, T),
	% the mix to verify
	posted(mix_signature(ConfigHash, Contest, MixHash, BallotsHash, 0, 0), T),
	% input ballots to mix came from the ballotbox
	posted(ballots(ConfigHash, Contest, BallotsHash), T),
	not posted(mix_signature(ConfigHash, Contest, MixHash, BallotsHash, 0, SelfT), T),
	a(A).

% check mix n
do(act_check_mix(ConfigHash, Contest, MixerT, MixHash, MixBallotsHash, PkHash), A, T) :-
	pk_ok(ConfigHash, Contest, PkHash, T),
	posted(config(ConfigHash, _, _, SelfT, A), T),
	config_ok(ConfigHash, T),
	% the mix to verify
	posted(mix_signature(ConfigHash, Contest, MixHash, MixBallotsHash, MixerT, SignerT), T),
	MixerT > 0,
	% input ballots to mix came from a previous mix, thus (mixer_t - 1)
	posted(mix_signaturey(ConfigHash, Contest, MixBallotsHash, _, MixerT - 1, SignerT), T),
	not posted(mix_signature(ConfigHash, Contest, MixHash, MixBallotsHash, MixerT, SelfT), T),
	a(A).

% input and output facts are shared with execution mode

%********** CONFIG **********%

config_ok(ConfigHash, T) :-
	posted(config(ConfigHash, _, TotalT, _, _), T),
	config_signed_upto(ConfigHash, TotalT - 1, T).

config_signed_upto(ConfigHash, 0, T) :-
	posted(config_signature(ConfigHash, 0), T).

config_signed_upto(ConfigHash, Trustee + 1, T) :-
    config_signed_upto(ConfigHash, Trustee, T),
    posted(config_signature(ConfigHash, Trustee + 1), T).

%********** SHARES **********%

pk_shares_ok(ConfigHash, Contest, Shares, T) :-
	posted(config(ConfigHash, _, TotalT, _, _), T),
	config_ok(ConfigHash, T),
	pk_shares_upto(ConfigHash, Contest, TotalT - 1, Shares, T).

pk_shares_upto(ConfigHash, Contest, 0, Share, T) :-
	posted(pk_share(ConfigHash, Contest, Share, 0), T).

pk_shares_upto(ConfigHash, Contest, Trustee + 1, @concat(Shares, Share), T) :-
    pk_shares_upto(ConfigHash, Contest, Trustee, Shares, T),
    posted(pk_share(ConfigHash, Contest, Share, Trustee + 1), T).


%********** PK SIGNATURES **********%

pk_ok(ConfigHash, Contest, PkHash, T) :-
	posted(config(ConfigHash, _, TotalT, _, _), T),
	config_ok(ConfigHash, T),
	pk_signed_upto(ConfigHash, Contest, PkHash, TotalT - 1, T).

pk_signed_upto(ConfigHash, Contest, PkHash, 0, T) :-
	posted(pk_signature(ConfigHash, Contest, PkHash, 0), T).

pk_signed_upto(ConfigHash, Contest, PkHash, Trustee + 1, T) :-
    pk_signed_upto(ConfigHash, Contest, PkHash, Trustee, T),
    posted(pk_signature(ConfigHash, Contest, PkHash, Trustee + 1), T).

%********** CONTEST **********%

contest(ConfigHash, Contests - 1, T) :-
	posted(config(ConfigHash, Contests, _, SelfT, _), T),
	t(T).
		
contest(ConfigHash, N - 1, T) :- contest(ConfigHash, N, T),
    N > 0.

 
%*******************************************************************************%

    
% work modeling
post(config_signature(ConfigHash, A), A, T + 1) :- do(act_sign_config(ConfigHash), A, T).
post(pk_share(ConfigHash, Contest, @concat2("share_hash", A), A), A, T + 1) :- do(act_post_share(ConfigHash, Contest), A, T).
post(pk_signature(ConfigHash, Contest, "pk_hash", A), A, T + 1) :- do(act_combine_shares(ConfigHash, Contest, Hashes), A, T).
post(pk_signature(ConfigHash, Contest, PkHash, A), A, T + 1) :- do(act_sign_pk(ConfigHash, Contest, PkHash, Hashes), A, T).
post(mix_signature(ConfigHash, Contest, @concat2("mix_hash_by", A), MixHash, A, A), A, T + 1) :- do(act_mix(ConfigHash, Contest, MixHash, PkHash), A, T).

% first to post on bb at time T wins
% select winner
1 { select(0..auths - 1, T) } 1 :- post(W, A, T), t(T).
% winner is posted
posted_at(W, A, T) :- post(W, A, T), select(A, T).
% integrity constraint: ensure that there is a successful post for each T at which 
% there is at least one post attempt. The last predicate is included to prevent 
% unsatisfiability in case the horizon does not reach the posted_at time
:- not posted_at(_, _, T), post(_, _, T), t(T).

% W was posted by time T if it was posted at T or earlier
% When running in execution mode, input facts must generate posted() predicates 
% with time 0 and auth 0: posted(W, 0, 0)
posted(W, T) :- posted_at(W, A, Past), Past <= T, t(T).

test(@concat("hello", "world")).

% #show posted_at/3.
% #show posted/2.
#show do/3.
% #show select/2.
% #show pk_shares_upto/5.
% #show pk_shares_ok/4.
% #show contest/3.
% #show config_signed_upto/3.
% #show config_ok/2.
% #show do/3.
% #show pk_signed_upto/5.
% #show pk_ok/4.