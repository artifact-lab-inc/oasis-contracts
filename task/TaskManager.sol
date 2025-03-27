// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IConsentManager} from "../../utils/interfaces/IConsentManager.sol";
import "./TaskQueue.sol";

/**
 * @title TaskManager
 * @dev Contract for managing a queue of tasks with authorized user access
 * @notice This contract provides a circular queue data structure to efficiently manage tasks.
 *         It allows for dynamic expansion of the queue capacity to accommodate growing demands.
 *         Tasks can be enqueued and dequeued, with events emitted for new task additions and task processing.
 *         Only authorized users can interact with certain functions.
 */
contract TaskManager is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    OwnableUpgradeable
{
    //Emitted when a new task is added to the queue.
    event NewTaskAdded(
        uint256 indexed taskId,
        uint256 indexed userId,
        uint256 dataType,
        string cId,
        string indexed taskType
    );

    // Emitted when a task is processed from the queue.
    event TaskProcessed(
        uint256 indexed taskRunnerId,
        uint256 taskId,
        uint256 indexed userId,
        uint256 dataType,
        string cId,
        string indexed taskType
    );

    // Emitted when an authorized user is added or removed
    event AuthorizedUserUpdated(address user, bool isAuthorized);

    /**
     * @dev Uses the TaskQueue library for QueueData
     */
    using TaskQueue for QueueData;

    /**
     * @dev Private queue data structure
     */
    QueueData private _soloQueue;

    uint256 private taskIdCounter; // Initialize a global counter

    IConsentManager public consentManagerContract;

    // Mapping to store authorized users
    mapping(address => bool) public authorizedUsers;

    // Modifier to restrict access to authorized users only
    modifier onlyAuthorized() {
        require(authorizedUsers[msg.sender], "Not authorized");
        _;
    }

    /**
     * Initializes the task manager with a specified queue size.
     *
     * @param queueSize The initial capacity of the circular queue.
     * @param _consentManagerAddress The address of the consent manager contract.
     */
    function initialize(
        uint256 queueSize,
        IConsentManager _consentManagerAddress
    ) public initializer {
        __Ownable_init(msg.sender);
        _soloQueue.initialize(queueSize);
        consentManagerContract = _consentManagerAddress;
        authorizedUsers[msg.sender] = true; // Add the contract deployer as an authorized user
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function updateConsentManagerContract(
        IConsentManager _consentManagerAddress
    ) external onlyOwner {
        consentManagerContract = _consentManagerAddress;
    }

    /**
     * Adds an authorized user to the contract.
     * @param user The address to be authorized.
     */
    function addAuthorizedUser(address user) external onlyOwner {
        authorizedUsers[user] = true;
        emit AuthorizedUserUpdated(user, true);
    }

    /**
     * Removes an authorized user from the contract.
     * @param user The address to be de-authorized.
     */
    function removeAuthorizedUser(address user) external onlyOwner {
        authorizedUsers[user] = false;
        emit AuthorizedUserUpdated(user, false);
    }

    /**
     * Dynamically expands the queue capacity if nearing fullness.
     *
     * @dev Checks if the current queue occupancy warrants expansion to prevent overflow.
     * Doubles the queue capacity if necessary to efficiently manage growing demands.
     *
     * @param minRequiredCapacity Minimum desired capacity threshold triggering potential expansions.
     */
    function _expandQueueSizeIfNeeded(uint256 minRequiredCapacity) internal {
    uint256 currentItemCount = _soloQueue.getItemCountInQueue();
    uint256 currentSize = _soloQueue.entries.length;
    
    // Note: TaskQueue adds +1 to capacity internally, so we need to account for that
    // The actual available space is currentSize - 1 - currentItemCount
    uint256 availableSpace = currentSize > 0 ? currentSize - 1 - currentItemCount : 0;
    
    if (availableSpace < minRequiredCapacity) {
        // Calculate new size: We need space for current items + required capacity + 1 (for circular buffer)
        uint256 minSize = currentItemCount + minRequiredCapacity + 1;
        
        // Double the size until it's big enough
        uint256 newSize = currentSize;
        while (newSize <= minSize) {
            newSize = newSize == 0 ? 2 : newSize * 2;
        }
        
        _soloQueue.resizeQueue(newSize - 1); // Subtract 1 because TaskQueue adds 1 internally
    }
}
    /**
     * Enqueues a new task into the managed queue, expanding capacity if necessary.
     * Only authorized users can call this function.
     *
     * @param userId IdentityId of user for whom the task is being enqueued
     * @param dataType type of data user stored
     * @param cId IPFS cid of the user's data
     * @param taskType Category/Type of the task.
     */
    function enqueueTask(
        uint256 userId,
        uint256 dataType,
        string calldata cId,
        string calldata taskType
    ) external onlyAuthorized {
        _expandQueueSizeIfNeeded(1); // Ensure at least one vacant slot exists
        taskIdCounter++; // Increment the global counter
        TaskEntry memory entry = TaskEntry(
            taskIdCounter,
            userId,
            dataType,
            cId,
            taskType
        );
        _soloQueue.push(entry);
        emit NewTaskAdded(taskIdCounter, userId, dataType, cId, taskType);
    }

    /**
     * Retrieves and removes the oldest task from the queue.
     * Only authorized users can call this function.
     * @param runnerId Unique Id associated with the Task Runner which will be responsible to process the task
     */
    function dequeueAndProcessNextTask(uint256 runnerId) external onlyAuthorized {
        consentManagerContract.validatePermit(msg.sender);
        TaskEntry memory nextTask = _soloQueue.pop();
        emit TaskProcessed(
            runnerId,
            nextTask.taskId,
            nextTask.userId,
            nextTask.dataType,
            nextTask.cId,
            nextTask.taskType
        );
    }

    /**
     * Returns an array containing all tasks currently stored in the queue.
     * Only authorized users can call this function.
     *
     * @return An array of TaskEntries representing pending tasks.
     */
    function getAllTasksInQueue() public view onlyAuthorized returns (TaskEntry[] memory) {
        uint256 count = _soloQueue.getItemCountInQueue();
        TaskEntry[] memory result = new TaskEntry[](count);

        uint256 currentIdx = (_soloQueue.head);
        for (uint256 idx = 0; idx < count; ++idx) {
            result[idx] = _soloQueue.entries[currentIdx];
            currentIdx = (currentIdx + 1) % _soloQueue.entries.length;
        }

        return result;
    }
}