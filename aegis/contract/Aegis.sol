pragma solidity ^0.5.1;

contract Aegis {

	address payable owner;
	uint deposit;
	uint voteDuration;
	uint revealDuration;
	uint totalVoters;

	enum ProposalType {Add, Remove}


	//Holds the details of a vote
	struct voteDetails {
		bytes32 ruleID;
		string rule;
		ProposalType voteType;
		address proposedBy;
		uint startBlock;
		uint voterAmount;
		uint forTally;
		uint againstTally;
		bool ended;
		bool used;
		mapping (address => bool) hasVoted;
	}

	//Holds deposits given by each voter, per vote
	struct VoteDeposit {
		address voter;
		bytes32 voteID;
		uint deposit;
	}

	//Record of allowed voters. Set to false in the event of removal of a voter
	mapping (address => bool) voter;

	//Mapping from voteId to voteDetails, identifies the voteDetails for each vote
	mapping (bytes32 => voteDetails) voteMap;

	//Mapping from userVoteID to deposit per user per vote
	mapping (bytes32 => VoteDeposit) deposits;

	//Mapping from userVoteID to deposit per user per vote
	mapping (bytes32 => bytes32) commitment;


	//Mapping from voteID to the string containing the pattern of the rule proposed for a vote
	mapping (bytes32 => string) rule;

	//List of all accepted rules
	bytes32[] ruleList;

	//Mapping from ruleID to array index. Used for removal from ruleList
	mapping(bytes32 => uint) ruleIndex;

	//Checks list of eligible voters
	modifier canVote() {
		require(voter[msg.sender] == true);
		_;
	}

	modifier isOwner() {
		require(msg.sender == owner);
		_;
	}

	//Checks if a vote is in progress
	modifier withinVoteWindow(bytes32 _voteID) {
		require(block.number < voteMap[_voteID].startBlock+voteDuration);
		require (!voteMap[_voteID].ended);
		_;
	}

	//Checks that voting window has ended and reveal is in progress
	modifier withinRevealWindow(bytes32 _voteID) {
		require(block.number > voteMap[_voteID].startBlock+voteDuration,"Voting still in progress");
		require(block.number < voteMap[_voteID].startBlock+voteDuration+revealDuration,"Reveal ended");
		_;
	}

	//Used to define deposit value and the lengths of votes and reveals. Adds the creator to the voters list
	constructor (uint _deposit, uint _voteDuration, uint _revealDuration) public {
		owner = msg.sender;
		voter[msg.sender] = true;
		totalVoters = 1;
		deposit = _deposit * 1 ether;
		voteDuration = _voteDuration;
		revealDuration = _revealDuration;

	}

//====================== Contract update functions ====================

	function transferOwnership(address payable _newOwner) external isOwner() {
		owner = _newOwner;
	}

	function changeVotingWindows(uint _deposit, uint _voteDuration, uint _revealDuration) external isOwner() {
		deposit = _deposit * 1 ether;
		voteDuration = _voteDuration;
		revealDuration = _revealDuration;
	}
//=====================================================================


//====================== Voter control functions ======================

		function addVoter(address _newVoter) external isOwner() {
		voter[_newVoter] = true;
		totalVoters += 1;
	}

		function removeVoter(address _newVoter) external isOwner() {
		voter[_newVoter] = false;
		totalVoters -= 1;
	}

//=====================================================================

	//Called by public proposal functions to initial a vote on a rule
	function addProposal(string memory _rule, address sndr, bool add) internal returns (bytes32 vote_ID) {
		bytes32 ruleID = keccak256(abi.encodePacked(_rule));
        bytes32 voteID;
		if (add) {
			voteID = keccak256(abi.encodePacked(ruleID,"add",sndr));
		}
		else {
			voteID = keccak256(abi.encodePacked(ruleID,"remove",sndr));	
		}

		//Check same vote does not already exist
		assert(voteMap[voteID].used == false);

        voteDetails storage vote = voteMap[voteID];
    
		vote.ruleID = ruleID;
		vote.rule = _rule;
		if (add) {
			vote.voteType = ProposalType.Add;
		}
		else {
			vote.voteType = ProposalType.Remove;
		}
		vote.proposedBy = msg.sender;
		vote.startBlock = block.number;
		vote.used = true;

		return voteID;
	}

//====================== public proposal functions ======================

	function proposeAdd(string memory _rule) public returns (bytes32 voteID){
		return addProposal(_rule, msg.sender, true);
	}

	function proposeRemove(string memory _rule) public returns (bytes32 voteID) {
		return addProposal(_rule, msg.sender, false);
	}

//=======================================================================

	//User specifies the vote they are participating in and sends their pre-calculated commiment along with the deposit
	function commitToVote(bytes32 _voteID, bytes32 _commitment) payable external canVote() withinVoteWindow(_voteID) returns (bool voted) {
		//require exact deposit amount, sending a larger deposit also triggers revert
		require(msg.value == deposit);
		bytes32 userVoteID = keccak256(abi.encodePacked(_voteID,msg.sender));
		VoteDeposit storage voteDeposit = deposits[userVoteID];

		voteDeposit.voter = msg.sender;
		voteDeposit.voteID = _voteID;
		voteDeposit.deposit = msg.value;

		voteMap[_voteID].voterAmount += 1;
		
		//hashed and signed commit created offchain and stored here.
		//commint format: H(voteID, vote, nonce)
		commitment[userVoteID] = _commitment;

		return true;
	}

	//User specifies the vote they are revealing for and sends the vote value and nonce used to create the commiment
	//If the stored commitment matches the recalculated one the vote is logged and the deposit is returned
	function revealVote(bytes32 _voteID, bool _vote, uint _nonce) external withinRevealWindow(_voteID) canVote(){
		bytes32 userVoteID = keccak256(abi.encodePacked(_voteID,msg.sender));
		require(commitment[userVoteID] > 0,"ID error");
		require(commitment[userVoteID] == keccak256(abi.encodePacked(_voteID,_vote,_nonce)),"commitment did not match");
		require(deposits[userVoteID].deposit >= deposit);
		
		if (!voteMap[_voteID].ended){
			if (_vote == true) {
			voteMap[_voteID].forTally += 1;
			}
			else if (_vote == false) {
			voteMap[_voteID].againstTally += 1;
			}
			updateRules(_voteID);			
		}

		msg.sender.transfer(deposit);
	}

	//Called when a vote passes successfully. Handles addition/removal of rule
	function updateRules(bytes32 _voteID) internal {
	    uint length;

		if (voteMap[_voteID].forTally > (voteMap[_voteID].voterAmount/2)) {

		    bytes32 ruleID = voteMap[_voteID].ruleID;
			if (voteMap[_voteID].voteType == ProposalType.Add) {
			    string memory ruleString = voteMap[_voteID].rule;
				rule[ruleID] = ruleString;
				length = ruleList.push(ruleID);
				ruleIndex[ruleID] = length-1;
			}
			else if (voteMap[_voteID].voteType == ProposalType.Remove) {
				delete rule[ruleID];
				delete ruleList[ruleIndex[ruleID]];
				delete ruleIndex[ruleID];
			}

			voteMap[_voteID].ended = true;
		}
	}
}