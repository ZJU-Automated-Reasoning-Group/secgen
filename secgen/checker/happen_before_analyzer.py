"""
Happen-Before Analyzer for C/C++

This module implements the main analyzer for happen-before relationships in C/C++ code.
It detects concurrency-related vulnerabilities and race conditions by analyzing
the ordering relationships between memory operations, synchronization primitives,
and threading operations.
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict

from secgen.core.models import CodeLocation, FunctionInfo
from secgen.ir.hb_graph import (
    HappenBeforeGraph, Event, EventType, SynchronizationType, 
    HappenBeforeRelation, RaceCondition, ConcurrencyPattern
)


class HappenBeforeAnalyzer:
    """Main analyzer for happen-before relationships in C/C++ code."""
    
    def __init__(self, logger=None):
        """Initialize the happen-before analyzer.
        
        Args:
            logger: Logger instance for debugging
        """
        self.logger = logger
        self.hb_graph = HappenBeforeGraph()
        self.event_counter = 0
        self.thread_counter = 0
        self.sync_objects = {}  # Track synchronization objects
        
        # Common synchronization function patterns
        self.lock_functions = {
            'pthread_mutex_lock', 'pthread_rwlock_rdlock', 'pthread_rwlock_wrlock',
            'pthread_spin_lock', 'sem_wait', 'WaitForSingleObject', 'EnterCriticalSection',
            'std::mutex::lock', 'std::unique_lock::lock', 'std::lock_guard::lock_guard'
        }
        
        self.unlock_functions = {
            'pthread_mutex_unlock', 'pthread_rwlock_unlock', 'pthread_spin_unlock',
            'sem_post', 'ReleaseMutex', 'LeaveCriticalSection',
            'std::mutex::unlock', 'std::unique_lock::unlock'
        }
        
        self.thread_functions = {
            'pthread_create', 'CreateThread', 'std::thread::thread',
            'pthread_join', 'WaitForSingleObject', 'std::thread::join'
        }
        
        self.atomic_functions = {
            'atomic_load', 'atomic_store', 'atomic_exchange', 'atomic_compare_exchange',
            'std::atomic::load', 'std::atomic::store', 'std::atomic::exchange',
            '__sync_fetch_and_add', '__sync_add_and_fetch', '__sync_bool_compare_and_swap'
        }
    
    def analyze_functions(self, functions: Dict[str, FunctionInfo]) -> HappenBeforeGraph:
        """Analyze happen-before relationships across multiple functions.
        
        Args:
            functions: Dictionary of function information
            
        Returns:
            HappenBeforeGraph with detected relationships
        """
        self.hb_graph = HappenBeforeGraph()
        
        # First pass: extract all events
        for func_id, func_info in functions.items():
            self._extract_events_from_function(func_id, func_info)
        
        # Second pass: establish happen-before relationships
        self._establish_happen_before_relationships()
        
        # Third pass: detect concurrency issues
        self.hb_graph.find_race_conditions()
        self.hb_graph.find_deadlocks()
        
        if self.logger:
            metrics = self.hb_graph.get_metrics()
            self.logger.log(f"Happen-before analysis complete: {metrics['num_events']} events, "
                          f"{metrics['num_race_conditions']} race conditions found")
        
        return self.hb_graph
    
    def _extract_events_from_function(self, func_id: str, func_info: FunctionInfo) -> None:
        """Extract events from a single function.
        
        Args:
            func_id: Function identifier
            func_info: Function information
        """
        # This is a simplified version - in practice, you'd parse the AST
        # and extract events based on the actual code structure
        
        # For now, we'll create placeholder events based on function calls
        for call in func_info.calls:
            if call in self.lock_functions:
                event = self._create_lock_event(func_id, func_info, call, EventType.LOCK_ACQUIRE)
                self.hb_graph.add_event(event)
            elif call in self.unlock_functions:
                event = self._create_lock_event(func_id, func_info, call, EventType.LOCK_RELEASE)
                self.hb_graph.add_event(event)
            elif call in self.thread_functions:
                event = self._create_thread_event(func_id, func_info, call)
                self.hb_graph.add_event(event)
            elif call in self.atomic_functions:
                event = self._create_atomic_event(func_id, func_info, call)
                self.hb_graph.add_event(event)
    
    def _create_lock_event(self, func_id: str, func_info: FunctionInfo, 
                          call_name: str, event_type: EventType) -> Event:
        """Create a lock-related event."""
        self.event_counter += 1
        event_id = f"event_{self.event_counter}"
        
        # Extract sync object name (simplified)
        sync_object = self._extract_sync_object_name(call_name)
        
        return Event(
            event_id=event_id,
            event_type=event_type,
            location=CodeLocation(
                file_path=func_info.file_path,
                line_start=func_info.start_line,
                line_end=func_info.end_line
            ),
            function_name=func_info.name,
            sync_object=sync_object,
            sync_type=self._get_sync_type(call_name),
            thread_id=self._get_current_thread_id()
        )
    
    def _create_thread_event(self, func_id: str, func_info: FunctionInfo, call_name: str) -> Event:
        """Create a thread-related event."""
        self.event_counter += 1
        event_id = f"event_{self.event_counter}"
        
        event_type = EventType.THREAD_CREATE if 'create' in call_name.lower() else EventType.THREAD_JOIN
        
        return Event(
            event_id=event_id,
            event_type=event_type,
            location=CodeLocation(
                file_path=func_info.file_path,
                line_start=func_info.start_line,
                line_end=func_info.end_line
            ),
            function_name=func_info.name,
            thread_id=self._get_current_thread_id()
        )
    
    def _create_atomic_event(self, func_id: str, func_info: FunctionInfo, call_name: str) -> Event:
        """Create an atomic operation event."""
        self.event_counter += 1
        event_id = f"event_{self.event_counter}"
        
        event_type = EventType.ATOMIC_READ if 'load' in call_name else EventType.ATOMIC_WRITE
        
        return Event(
            event_id=event_id,
            event_type=event_type,
            location=CodeLocation(
                file_path=func_info.file_path,
                line_start=func_info.start_line,
                line_end=func_info.end_line
            ),
            function_name=func_info.name,
            is_atomic=True,
            memory_order='seq_cst'  # Default memory ordering
        )
    
    def _extract_sync_object_name(self, call_name: str) -> str:
        """Extract synchronization object name from function call."""
        # This is simplified - in practice, you'd parse the actual arguments
        return f"sync_obj_{hash(call_name) % 1000}"
    
    def _get_sync_type(self, call_name: str) -> SynchronizationType:
        """Determine synchronization type from function name."""
        if 'mutex' in call_name:
            return SynchronizationType.MUTEX
        elif 'sem' in call_name:
            return SynchronizationType.SEMAPHORE
        elif 'rwlock' in call_name:
            return SynchronizationType.READ_WRITE_LOCK
        elif 'spin' in call_name:
            return SynchronizationType.SPINLOCK
        else:
            return SynchronizationType.MUTEX
    
    def _get_current_thread_id(self) -> str:
        """Get current thread identifier."""
        return f"thread_{self.thread_counter}"
    
    def _establish_happen_before_relationships(self) -> None:
        """Establish happen-before relationships between events."""
        events = list(self.hb_graph.events.values())
        
        # Program order within same thread
        self._establish_program_order_relations(events)
        
        # Synchronization relationships
        self._establish_synchronization_relations(events)
        
        # Transitive closure
        self._compute_transitive_relations()
    
    def _establish_program_order_relations(self, events: List[Event]) -> None:
        """Establish program order relationships within threads."""
        # Group events by thread
        thread_events = defaultdict(list)
        for event in events:
            thread_id = event.thread_id or 'main'
            thread_events[thread_id].append(event)
        
        # Create program order relations
        for thread_id, thread_event_list in thread_events.items():
            # Sort by line number (simplified ordering)
            thread_event_list.sort(key=lambda e: e.location.line_start)
            
            for i in range(len(thread_event_list) - 1):
                relation = HappenBeforeRelation(
                    before_event=thread_event_list[i].event_id,
                    after_event=thread_event_list[i + 1].event_id,
                    relation_type='program_order',
                    confidence=1.0,
                    evidence=f"Program order in thread {thread_id}"
                )
                self.hb_graph.add_happen_before_relation(relation)
    
    def _establish_synchronization_relations(self, events: List[Event]) -> None:
        """Establish synchronization relationships between events."""
        # Find lock/unlock pairs
        lock_events = [e for e in events if e.event_type == EventType.LOCK_ACQUIRE]
        unlock_events = [e for e in events if e.event_type == EventType.LOCK_RELEASE]
        
        for lock_event in lock_events:
            for unlock_event in unlock_events:
                if (lock_event.sync_object == unlock_event.sync_object and
                    lock_event.thread_id == unlock_event.thread_id):
                    # All events between lock and unlock happen after lock
                    # and before unlock
                    self._create_sync_relations(lock_event, unlock_event, events)
    
    def _create_sync_relations(self, lock_event: Event, unlock_event: Event, 
                              all_events: List[Event]) -> None:
        """Create synchronization relations for a lock/unlock pair."""
        # Find events that happen between lock and unlock
        between_events = [
            e for e in all_events
            if (e.location.line_start > lock_event.location.line_start and
                e.location.line_start < unlock_event.location.line_start and
                e.thread_id == lock_event.thread_id)
        ]
        
        # Lock happens before all events in critical section
        for event in between_events:
            relation = HappenBeforeRelation(
                before_event=lock_event.event_id,
                after_event=event.event_id,
                relation_type='synchronization',
                sync_object=lock_event.sync_object,
                confidence=1.0,
                evidence=f"Lock {lock_event.sync_object} protects event"
            )
            self.hb_graph.add_happen_before_relation(relation)
        
        # All events in critical section happen before unlock
        for event in between_events:
            relation = HappenBeforeRelation(
                before_event=event.event_id,
                after_event=unlock_event.event_id,
                relation_type='synchronization',
                sync_object=lock_event.sync_object,
                confidence=1.0,
                evidence=f"Event protected by lock {lock_event.sync_object}"
            )
            self.hb_graph.add_happen_before_relation(relation)
    
    def _compute_transitive_relations(self) -> None:
        """Compute transitive closure of happen-before relations."""
        # This is handled by NetworkX's transitive_closure method
        # when we call get_happen_before_closure()
        pass
    
    def get_analysis_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results.
        
        Returns:
            Dictionary containing all analysis results
        """
        return {
            'graph': self.hb_graph,
            'race_conditions': self.hb_graph.race_conditions,
            'concurrency_patterns': self.hb_graph.concurrency_patterns,
            'metrics': self.hb_graph.get_metrics(),
            'events': list(self.hb_graph.events.values()),
            'relations': self.hb_graph.relations
        }
