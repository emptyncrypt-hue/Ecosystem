// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title GACC Node Access Control List (ACL) Contract
 * @author Technical Architecture Team (EXO Revision)
 * @notice Enforces zero-trust cryptographic node validation via immutable state hashes.
 * @dev Designed for private consensus infrastructure within the Dune-sub Org ecosystem.
 * Copyright © 2026 Dune-sub Org. All Rights Reserved.
 */
contract NodeAccessControl {

    enum NodeStatus { NonExistent, Active, Suspended, Quarantined }

    struct NodeMetadata {
        bytes32 certificateHash;
        string hardwareAttestationType;
        NodeStatus status;
        uint256 lastSeenTimestamp;
    }

    address public immutable ecosystemGovernance;
    mapping(string => NodeMetadata) private registry;
    mapping(address => bool) private authorizedOperators;

    event NodeRegistered(string indexed nodeId, bytes32 certificateHash, string attestationType);
    event NodeStatusUpdated(string indexed nodeId, NodeStatus oldStatus, NodeStatus newStatus);
    event NodeIdentityValidated(string indexed nodeId, address indexed executionContext, uint256 timestamp);

    modifier onlyGovernance() {
        require(msg.sender == ecosystemGovernance, "AuthError: Requester must be central governance");
        _;
    }

    modifier onlyOperator() {
        require(authorizedOperators[msg.sender] || msg.sender == ecosystemGovernance, "AuthError: Requester unauthorized");
        _;
    }

    constructor() {
        ecosystemGovernance = msg.sender;
        authorizedOperators[msg.sender] = true;
    }

    function toggleOperator(address operator, bool state) external onlyGovernance {
        authorizedOperators[operator] = state;
    }

    function registerNode(
        string calldata nodeId,
        bytes32 certHash,
        string calldata attestationType
    ) external onlyOperator {
        require(registry[nodeId].status == NodeStatus.NonExistent, "RegistryError: Node entry already initialized");
        require(certHash != bytes32(0), "ValidationError: Signature token payload empty");

        registry[nodeId] = NodeMetadata({
            certificateHash: certHash,
            hardwareAttestationType: attestationType,
            status: NodeStatus.Active,
            lastSeenTimestamp: block.timestamp
        });

        emit NodeRegistered(nodeId, certHash, attestationType);
    }

    function updateNodeStatus(string calldata nodeId, NodeStatus targetStatus) external onlyOperator {
        require(registry[nodeId].status != NodeStatus.NonExistent, "RegistryError: Targeted identifier unregistered");
        NodeStatus existingStatus = registry[nodeId].status;
        registry[nodeId].status = targetStatus;
        registry[nodeId].lastSeenTimestamp = block.timestamp;

        emit NodeStatusUpdated(nodeId, existingStatus, targetStatus);
    }

    function verifyNodeState(string calldata nodeId, bytes32 certHash) external view returns (bool) {
        NodeMetadata memory node = registry[nodeId];
        if (node.status != NodeStatus.Active) return false;
        return (node.certificateHash == certHash);
    }

    function heartbeat(string calldata nodeId) external onlyOperator {
        require(registry[nodeId].status == NodeStatus.Active, "StateError: Node isolated or offline");
        registry[nodeId].lastSeenTimestamp = block.timestamp;
        emit NodeIdentityValidated(nodeId, msg.sender, block.timestamp);
    }
}
