from enum import Enum

class TaskStatus(Enum):
    New = "New"
    Runnable = "Runnable"
    Running = "Running"
    Blocked = "Blocked"
    Terminated = "Terminated"