// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Represents a single task entry in the queue
 * @notice Contains a unique task ID, transaction hash where certain task's event got emitted and type of task
 */
struct TaskEntry {
    uint256 taskId;
    uint256 userId;
    uint256 dataType;
    string cId;
    string taskType;
}

/**
 * @dev Represents the queue data structure
 * @notice Contains an array of task entries, as well as head and tail indices
 */
struct QueueData {
    TaskEntry[] entries;
    uint256 head;
    uint256 tail;
}

// Error thrown when the queue capacity is exceeded
error CapacityExceeded();

// Error thrown when attempting to dequeue from an empty queue
error UnderflowDetected();

// Error thrown when attempting to initialize a queue with zero capacity
error ZeroCapacityNotAllowed();

// Error thrown when attempting to resize the queue to a capacity that is insufficient
error CapacityInsufficientForResize();

/**
 * @title TaskQueue
 * @dev Library for managing a circular queue of tasks
 * @notice Provides functions for initializing, resizing, and manipulating a queue of tasks
 */
library TaskQueue {
    /**
     * @dev Initializes a queue with a specified capacity
     * @param self Reference to the Queue structure being initialized
     * @param capacity Initial capacity of the queue
     */
    function initialize(QueueData storage self, uint256 capacity) internal {
        if (capacity == 0) revert ZeroCapacityNotAllowed();
        self.entries = new TaskEntry[](capacity + 1); // Edge-case handling (+1)
    }

    /**
     * Resizes the underlying queue to accommodate growing demands.
     *
     * @dev Reallocates the queue to hold at least 'newCapacity' elements,
     * ensuring sufficient space for future additions without excessive reallocations.
     *
     * @param self Reference to the Queue structure being resized.
     * @param newCapacity Desired minimal capacity after reallocation.
     */
    function resizeQueue(QueueData storage self, uint256 newCapacity) internal {
        if (newCapacity == 0) revert ZeroCapacityNotAllowed();

        if (newCapacity <= getItemCountInQueue(self)) {
            revert CapacityInsufficientForResize();
        }

        TaskEntry[] memory oldEntries = self.entries;
        self.entries = new TaskEntry[](newCapacity + 1); // Allocate new queue with increased capacity

        uint256 itemCount = getItemCountInQueue(self);
        for (uint256 i; i < itemCount; ++i) {
            uint256 oldIndex = (self.head + i) % oldEntries.length;
            uint256 newIndex = (self.head + i) % self.entries.length;

            self.entries[newIndex] = oldEntries[oldIndex];
        }

        self.head = 0;
        self.tail = itemCount;
    }

    /**
     * @dev Returns the number of items in the queue
     * @param self Reference to the Queue structure
     * @return Number of items in the queue
     */
    function getItemCountInQueue(
        QueueData storage self
    ) internal view returns (uint256) {
        return
            self.tail >= self.head
                ? self.tail - self.head
                : self.entries.length + self.tail - self.head;
    }

    /**
     * @dev Adds a new item to the end of the queue
     * @param self Reference to the Queue structure
     * @param element Item to add to the queue
     */
    function push(QueueData storage self, TaskEntry memory element) internal {
        if ((self.tail + 1) % self.entries.length == self.head) {
            revert CapacityExceeded();
        }

        self.entries[self.tail].taskId = element.taskId;
        self.entries[self.tail].userId = element.userId;
        self.entries[self.tail].dataType = element.dataType;
        self.entries[self.tail].cId = element.cId;
        self.entries[self.tail].taskType = element.taskType;
        self.tail = (self.tail + 1) % self.entries.length;
    }

    /**
     * @dev Removes and returns the item at the front of the queue
     * @param self Reference to the Queue structure
     * @return Item removed from the queue
     */
    function pop(QueueData storage self) internal returns (TaskEntry memory) {
        if (self.head == self.tail) {
            revert UnderflowDetected();
        }

        TaskEntry memory removedElement = self.entries[self.head];

        unchecked {
            // Safe arithmetic operation due to underflow check above
            self.head += 1;
            self.head %= self.entries.length;
        }

        return removedElement;
    }
}
