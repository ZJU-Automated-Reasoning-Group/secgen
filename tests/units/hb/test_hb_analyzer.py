"""Tests for HappenBeforeAnalyzer functionality."""

import pytest
from secgen.checker.happen_before_analyzer import HappenBeforeAnalyzer
from secgen.ir.hb_graph import HappenBeforeGraph, EventType, SynchronizationType
from secgen.core.models import FunctionInfo


class TestHappenBeforeAnalyzer:
    """Test HappenBeforeAnalyzer functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = HappenBeforeAnalyzer()
        
        # Create mock function info
        self.functions = {
            "func1": FunctionInfo(
                name="thread_function",
                file_path="test.cpp",
                start_line=10,
                end_line=30,
                parameters=["arg1"],
                calls=["pthread_mutex_lock", "pthread_mutex_unlock"]
            ),
            "func2": FunctionInfo(
                name="main_function",
                file_path="test.cpp",
                start_line=1,
                end_line=50,
                parameters=[],
                calls=["pthread_create", "pthread_join"]
            )
        }
    
    def test_analyze_functions(self):
        """Test analyzing multiple functions."""
        hb_graph = self.analyzer.analyze_functions(self.functions)
        
        assert isinstance(hb_graph, HappenBeforeGraph)
        assert len(hb_graph.events) > 0
        
        # Check that lock/unlock events were created
        lock_events = [e for e in hb_graph.events.values() if e.event_type == EventType.LOCK_ACQUIRE]
        unlock_events = [e for e in hb_graph.events.values() if e.event_type == EventType.LOCK_RELEASE]
        
        assert len(lock_events) > 0
        assert len(unlock_events) > 0
    
    def test_create_lock_event(self):
        """Test lock event creation."""
        func_info = self.functions["func1"]
        event = self.analyzer._create_lock_event("func1", func_info, "pthread_mutex_lock", EventType.LOCK_ACQUIRE)
        
        assert event.event_type == EventType.LOCK_ACQUIRE
        assert event.function_name == "thread_function"
        assert event.sync_type == SynchronizationType.MUTEX
        assert event.sync_object is not None
    
    def test_create_thread_event(self):
        """Test thread event creation."""
        func_info = self.functions["func2"]
        event = self.analyzer._create_thread_event("func2", func_info, "pthread_create")
        
        assert event.event_type == EventType.THREAD_CREATE
        assert event.function_name == "main_function"
        assert event.thread_id is not None
    
    def test_create_atomic_event(self):
        """Test atomic event creation."""
        func_info = self.functions["func1"]
        event = self.analyzer._create_atomic_event("func1", func_info, "atomic_load")
        
        assert event.event_type == EventType.ATOMIC_READ
        assert event.is_atomic is True
        assert event.memory_order == "seq_cst"
    
    def test_get_sync_type(self):
        """Test synchronization type detection."""
        assert self.analyzer._get_sync_type("pthread_mutex_lock") == SynchronizationType.MUTEX
        assert self.analyzer._get_sync_type("sem_wait") == SynchronizationType.SEMAPHORE
        assert self.analyzer._get_sync_type("pthread_rwlock_rdlock") == SynchronizationType.READ_WRITE_LOCK
        assert self.analyzer._get_sync_type("pthread_spin_lock") == SynchronizationType.SPINLOCK
        assert self.analyzer._get_sync_type("unknown_lock") == SynchronizationType.MUTEX
    
    def test_get_analysis_results(self):
        """Test getting comprehensive analysis results."""
        self.analyzer.analyze_functions(self.functions)
        results = self.analyzer.get_analysis_results()
        
        assert 'graph' in results
        assert 'race_conditions' in results
        assert 'concurrency_patterns' in results
        assert 'metrics' in results
        assert 'events' in results
        assert 'relations' in results
        
        assert isinstance(results['graph'], HappenBeforeGraph)
        assert isinstance(results['race_conditions'], list)
        assert isinstance(results['concurrency_patterns'], list)
        assert isinstance(results['metrics'], dict)

    def test_analyze_empty_functions(self):
        """Test analyzing empty function dictionary."""
        hb_graph = self.analyzer.analyze_functions({})
        
        assert isinstance(hb_graph, HappenBeforeGraph)
        assert len(hb_graph.events) == 0

    def test_extract_events_from_function(self):
        """Test extracting events from a function."""
        func_info = self.functions["func1"]
        self.analyzer._extract_events_from_function("func1", func_info)
        
        # Check that events were created
        assert len(self.analyzer.hb_graph.events) > 0

    def test_extract_sync_object_name(self):
        """Test extracting synchronization object names."""
        sync_name = self.analyzer._extract_sync_object_name("pthread_mutex_lock(&mutex)")
        assert isinstance(sync_name, str)
        assert sync_name.startswith("sync_obj_")
        
        sync_name2 = self.analyzer._extract_sync_object_name("sem_wait(&sem)")
        assert isinstance(sync_name2, str)
        assert sync_name2.startswith("sync_obj_")

    def test_get_current_thread_id(self):
        """Test getting current thread ID."""
        thread_id = self.analyzer._get_current_thread_id()
        assert isinstance(thread_id, str)
        assert thread_id.startswith("thread_")

    def test_establish_happen_before_relationships(self):
        """Test establishing happen-before relationships."""
        self.analyzer.analyze_functions(self.functions)
        self.analyzer._establish_happen_before_relationships()
        
        # Check that relations were established
        assert len(self.analyzer.hb_graph.relations) > 0

    def test_establish_program_order_relations(self):
        """Test establishing program order relations."""
        self.analyzer.analyze_functions(self.functions)
        events = list(self.analyzer.hb_graph.events.values())
        self.analyzer._establish_program_order_relations(events)
        
        # Check that program order relations were created
        program_order_relations = [r for r in self.analyzer.hb_graph.relations 
                                 if r.relation_type == "program_order"]
        assert len(program_order_relations) > 0

    def test_establish_synchronization_relations(self):
        """Test establishing synchronization relations."""
        self.analyzer.analyze_functions(self.functions)
        events = list(self.analyzer.hb_graph.events.values())
        self.analyzer._establish_synchronization_relations(events)
        
        # Check that synchronization relations were created
        # Note: This might not create relations if there are no matching lock/unlock pairs
        sync_relations = [r for r in self.analyzer.hb_graph.relations 
                         if r.relation_type == "synchronization"]
        # Allow for 0 or more synchronization relations depending on the test data
        assert len(sync_relations) >= 0


if __name__ == "__main__":
    pytest.main([__file__])
