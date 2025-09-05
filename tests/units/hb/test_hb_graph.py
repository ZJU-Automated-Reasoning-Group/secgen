"""Tests for HappenBeforeGraph functionality."""

import pytest
from secgen.ir.hb_graph import (
    HappenBeforeGraph, Event, EventType, 
    SynchronizationType, HappenBeforeRelation
)
from secgen.core.models import CodeLocation


class TestHappenBeforeGraph:
    """Test HappenBeforeGraph functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.graph = HappenBeforeGraph()
        
        # Create test events
        self.event1 = Event(
            event_id="event_1",
            event_type=EventType.MEMORY_WRITE,
            location=CodeLocation("test.cpp", 10, 10),
            function_name="func1",
            variable_name="shared_var",
            thread_id="thread_1"
        )
        
        self.event2 = Event(
            event_id="event_2",
            event_type=EventType.MEMORY_READ,
            location=CodeLocation("test.cpp", 20, 20),
            function_name="func2",
            variable_name="shared_var",
            thread_id="thread_2"
        )
    
    def test_add_event(self):
        """Test adding events to the graph."""
        self.graph.add_event(self.event1)
        assert self.event1.event_id in self.graph.events
        assert self.event1.event_id in self.graph.graph.nodes()
    
    def test_add_happen_before_relation(self):
        """Test adding happen-before relations."""
        self.graph.add_event(self.event1)
        self.graph.add_event(self.event2)
        
        relation = HappenBeforeRelation(
            before_event="event_1",
            after_event="event_2",
            relation_type="program_order"
        )
        
        self.graph.add_happen_before_relation(relation)
        assert len(self.graph.relations) == 1
        assert self.graph.graph.has_edge("event_1", "event_2")
    
    def test_find_race_conditions(self):
        """Test race condition detection."""
        self.graph.add_event(self.event1)
        self.graph.add_event(self.event2)
        
        race_conditions = self.graph.find_race_conditions()
        assert len(race_conditions) == 1
        assert race_conditions[0].variable_name == "shared_var"
    
    def test_find_deadlocks(self):
        """Test deadlock detection."""
        event_lock1 = Event(
            event_id="lock1",
            event_type=EventType.LOCK_ACQUIRE,
            location=CodeLocation("test.cpp", 10, 10),
            function_name="func1",
            sync_object="mutex_1",
            thread_id="thread_1"
        )
        
        event_lock2 = Event(
            event_id="lock2",
            event_type=EventType.LOCK_ACQUIRE,
            location=CodeLocation("test.cpp", 20, 20),
            function_name="func2",
            sync_object="mutex_2",
            thread_id="thread_2"
        )
        
        self.graph.add_event(event_lock1)
        self.graph.add_event(event_lock2)
        
        deadlocks = self.graph.find_deadlocks()
        assert isinstance(deadlocks, list)
    
    def test_get_metrics(self):
        """Test metrics calculation."""
        self.graph.add_event(self.event1)
        self.graph.add_event(self.event2)
        
        metrics = self.graph.get_metrics()
        assert metrics['num_events'] == 2
        assert metrics['num_relations'] == 0

    def test_happen_before_closure(self):
        """Test getting happen-before closure."""
        self.graph.add_event(self.event1)
        self.graph.add_event(self.event2)
        
        relation = HappenBeforeRelation(
            before_event="event_1",
            after_event="event_2",
            relation_type="program_order"
        )
        self.graph.add_happen_before_relation(relation)
        
        closure = self.graph.get_happen_before_closure()
        assert isinstance(closure, type(self.graph.graph))
        assert closure.has_edge("event_1", "event_2")

    def test_graph_structure(self):
        """Test the underlying NetworkX graph structure."""
        self.graph.add_event(self.event1)
        self.graph.add_event(self.event2)
        
        assert self.graph.graph.number_of_nodes() == 2
        assert self.graph.graph.number_of_edges() == 0
        
        relation = HappenBeforeRelation(
            before_event="event_1",
            after_event="event_2",
            relation_type="program_order"
        )
        self.graph.add_happen_before_relation(relation)
        
        assert self.graph.graph.number_of_edges() == 1

if __name__ == "__main__":
    pytest.main([__file__])
