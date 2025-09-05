"""
Happen-Before Graph Analysis for C/C++
"""

import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from secgen.core.models import CodeLocation, FunctionInfo
from secgen.ir.models import CallSite



class EventType(Enum):
    """Types of events in happen-before analysis."""
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    LOCK_ACQUIRE = "lock_acquire"
    LOCK_RELEASE = "lock_release"
    THREAD_CREATE = "thread_create"
    THREAD_JOIN = "thread_join"
    CONDITION_WAIT = "condition_wait"
    CONDITION_SIGNAL = "condition_signal"
    BARRIER_WAIT = "barrier_wait"
    ATOMIC_READ = "atomic_read"
    ATOMIC_WRITE = "atomic_write"
    FUNCTION_CALL = "function_call"
    FUNCTION_RETURN = "function_return"


class SynchronizationType(Enum):
    """Types of synchronization primitives."""
    MUTEX = "mutex"
    SEMAPHORE = "semaphore"
    CONDITION_VARIABLE = "condition_variable"
    BARRIER = "barrier"
    ATOMIC = "atomic"
    SPINLOCK = "spinlock"
    READ_WRITE_LOCK = "read_write_lock"


@dataclass
class Event:
    """Represents an event in the happen-before analysis."""
    event_id: str
    event_type: EventType
    location: CodeLocation
    function_name: str
    variable_name: Optional[str] = None
    thread_id: Optional[str] = None
    sync_object: Optional[str] = None
    sync_type: Optional[SynchronizationType] = None
    is_atomic: bool = False
    memory_order: Optional[str] = None  # For atomic operations
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HappenBeforeRelation:
    """Represents a happen-before relationship between two events."""
    before_event: str  # Event ID
    after_event: str   # Event ID
    relation_type: str  # 'program_order', 'synchronization', 'transitive'
    sync_object: Optional[str] = None
    confidence: float = 1.0
    evidence: str = ""


@dataclass
class RaceCondition:
    """Represents a detected race condition."""
    location1: CodeLocation
    location2: CodeLocation
    variable_name: str
    event1: Event
    event2: Event
    severity: str  # 'high', 'medium', 'low'
    description: str
    recommendation: str
    confidence: float


@dataclass
class ConcurrencyIssue:
    """Represents a concurrency-related issue found during analysis."""
    issue_type: str  # 'race_condition', 'deadlock', 'data_race', etc.
    severity: str    # 'high', 'medium', 'low'
    description: str
    locations: List[CodeLocation]
    confidence: float
    recommendation: str


@dataclass
class ConcurrencyPattern:
    """Represents a detected concurrency pattern."""
    pattern_type: str  # 'double_lock', 'deadlock', 'lock_order_violation', etc.
    events: List[Event]
    locations: List[CodeLocation]
    description: str
    severity: str
    recommendation: str


class HappenBeforeGraph:
    """Graph representing happen-before relationships between events."""
    
    def __init__(self):
        """Initialize the happen-before graph."""
        self.graph = nx.DiGraph()
        self.events: Dict[str, Event] = {}
        self.relations: List[HappenBeforeRelation] = []
        self.race_conditions: List[RaceCondition] = []
        self.concurrency_patterns: List[ConcurrencyPattern] = []
        
    def add_event(self, event: Event) -> None:
        """Add an event to the graph."""
        self.events[event.event_id] = event
        self.graph.add_node(event.event_id, event=event)
        
    def add_happen_before_relation(self, relation: HappenBeforeRelation) -> None:
        """Add a happen-before relation between two events."""
        if relation.before_event in self.events and relation.after_event in self.events:
            self.relations.append(relation)
            self.graph.add_edge(
                relation.before_event, 
                relation.after_event,
                relation=relation
            )
    
    def get_happen_before_closure(self) -> nx.DiGraph:
        """Get the transitive closure of happen-before relationships."""
        return nx.transitive_closure(self.graph)
    
    def find_race_conditions(self) -> List[RaceCondition]:
        """Find potential race conditions in the graph."""
        race_conditions = []
        
        # Group events by variable and thread
        variable_events = defaultdict(lambda: defaultdict(list))
        for event in self.events.values():
            if event.variable_name and event.event_type in [EventType.MEMORY_READ, EventType.MEMORY_WRITE]:
                variable_events[event.variable_name][event.thread_id or 'main'].append(event)
        
        # Check for races between different threads
        for var_name, thread_events in variable_events.items():
            threads = list(thread_events.keys())
            for i, thread1 in enumerate(threads):
                for thread2 in threads[i+1:]:
                    for event1 in thread_events[thread1]:
                        for event2 in thread_events[thread2]:
                            if not self._has_happen_before_relation(event1.event_id, event2.event_id):
                                race_condition = self._create_race_condition(event1, event2, var_name)
                                if race_condition:
                                    race_conditions.append(race_condition)
        
        self.race_conditions = race_conditions
        return race_conditions
    
    def _has_happen_before_relation(self, event1_id: str, event2_id: str) -> bool:
        """Check if there's a happen-before relation between two events."""
        try:
            return nx.has_path(self.graph, event1_id, event2_id)
        except:
            return False
    
    def _create_race_condition(self, event1: Event, event2: Event, var_name: str) -> Optional[RaceCondition]:
        """Create a race condition object from two events."""
        # Determine severity based on operation types
        if event1.event_type == EventType.MEMORY_WRITE and event2.event_type == EventType.MEMORY_WRITE:
            severity = 'high'
            description = f"Race condition: concurrent writes to variable '{var_name}'"
        elif event1.event_type == EventType.MEMORY_WRITE or event2.event_type == EventType.MEMORY_WRITE:
            severity = 'medium'
            description = f"Race condition: concurrent read/write to variable '{var_name}'"
        else:
            severity = 'low'
            description = f"Race condition: concurrent reads to variable '{var_name}'"
        
        recommendation = f"Use synchronization primitives (mutex, atomic operations) to protect access to '{var_name}'"
        
        return RaceCondition(
            location1=event1.location,
            location2=event2.location,
            variable_name=var_name,
            event1=event1,
            event2=event2,
            severity=severity,
            description=description,
            recommendation=recommendation,
            confidence=0.8
        )
    
    def find_deadlocks(self) -> List[ConcurrencyPattern]:
        """Find potential deadlock patterns."""
        deadlocks = []
        
        # Find cycles in the lock acquisition graph
        lock_graph = nx.DiGraph()
        lock_acquisitions = {}
        
        for event in self.events.values():
            if event.event_type == EventType.LOCK_ACQUIRE and event.sync_object:
                lock_acquisitions[event.thread_id] = event.sync_object
            elif event.event_type == EventType.LOCK_RELEASE and event.sync_object:
                if event.thread_id in lock_acquisitions:
                    del lock_acquisitions[event.thread_id]
        
        # Build lock dependency graph
        for thread_id, lock_obj in lock_acquisitions.items():
            for other_thread_id, other_lock_obj in lock_acquisitions.items():
                if thread_id != other_thread_id and lock_obj != other_lock_obj:
                    lock_graph.add_edge(thread_id, other_thread_id, lock=lock_obj)
        
        # Find cycles
        try:
            cycles = list(nx.simple_cycles(lock_graph))
            for cycle in cycles:
                if len(cycle) > 1:  # Only consider cycles with multiple threads
                    events_in_cycle = []
                    locations_in_cycle = []
                    
                    for thread_id in cycle:
                        thread_events = [e for e in self.events.values() if e.thread_id == thread_id]
                        events_in_cycle.extend(thread_events)
                        locations_in_cycle.extend([e.location for e in thread_events])
                    
                    deadlock = ConcurrencyPattern(
                        pattern_type='deadlock',
                        events=events_in_cycle,
                        locations=locations_in_cycle,
                        description=f"Potential deadlock involving threads: {', '.join(cycle)}",
                        severity='high',
                        recommendation="Review lock ordering to prevent circular dependencies"
                    )
                    deadlocks.append(deadlock)
        except:
            pass
        
        return deadlocks
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics about the happen-before graph."""
        return {
            'num_events': len(self.events),
            'num_relations': len(self.relations),
            'num_race_conditions': len(self.race_conditions),
            'num_concurrency_patterns': len(self.concurrency_patterns),
            'graph_density': nx.density(self.graph),
            'is_acyclic': nx.is_directed_acyclic_graph(self.graph),
            'strongly_connected_components': len(list(nx.strongly_connected_components(self.graph)))
        }


