"""Tests for race condition detection scenarios."""

import pytest
from secgen.ir.hb_graph import (
    HappenBeforeGraph, Event, EventType, 
    HappenBeforeRelation, SynchronizationType
)
from secgen.core.models import CodeLocation


class TestRaceConditionDetection:
    """Test race condition detection scenarios."""
    
    def _create_event(self, event_id, event_type, line, var_name="shared_var", thread_id="thread_1"):
        """Helper to create events with common defaults."""
        return Event(
            event_id=event_id,
            event_type=event_type,
            location=CodeLocation("test.cpp", line, line),
            function_name="func",
            variable_name=var_name,
            thread_id=thread_id
        )
    
    def test_basic_race_conditions(self):
        """Test basic write-write and read-write race conditions."""
        graph = HappenBeforeGraph()
        
        # Write-write race (high severity)
        write1 = self._create_event("write1", EventType.MEMORY_WRITE, 10, "shared_var", "thread_1")
        write2 = self._create_event("write2", EventType.MEMORY_WRITE, 20, "shared_var", "thread_2")
        
        # Read-write race (medium severity)  
        read1 = self._create_event("read1", EventType.MEMORY_READ, 30, "var2", "thread_1")
        write3 = self._create_event("write3", EventType.MEMORY_WRITE, 40, "var2", "thread_2")
        
        for event in [write1, write2, read1, write3]:
            graph.add_event(event)
        
        race_conditions = graph.find_race_conditions()
        assert len(race_conditions) == 2
        
        # Check severities
        high_severity = [rc for rc in race_conditions if rc.severity == "high"]
        medium_severity = [rc for rc in race_conditions if rc.severity == "medium"]
        assert len(high_severity) == 1
        assert len(medium_severity) == 1
    
    def test_no_race_scenarios(self):
        """Test scenarios that should not create race conditions."""
        graph = HappenBeforeGraph()
        
        # Same thread - no race
        write1 = self._create_event("write1", EventType.MEMORY_WRITE, 10, "shared_var", "thread_1")
        write2 = self._create_event("write2", EventType.MEMORY_WRITE, 20, "shared_var", "thread_1")
        
        # Different variables - no race
        write3 = self._create_event("write3", EventType.MEMORY_WRITE, 30, "var1", "thread_2")
        write4 = self._create_event("write4", EventType.MEMORY_WRITE, 40, "var2", "thread_3")
        
        for event in [write1, write2, write3, write4]:
            graph.add_event(event)
        
        race_conditions = graph.find_race_conditions()
        assert len(race_conditions) == 0
    
    def test_synchronized_access(self):
        """Test that synchronized access prevents race conditions."""
        graph = HappenBeforeGraph()
        
        # Create synchronized access pattern
        lock_event = Event(
            event_id="lock1",
            event_type=EventType.LOCK_ACQUIRE,
            location=CodeLocation("test.cpp", 5, 5),
            function_name="func1",
            sync_object="mutex_1",
            thread_id="thread_1"
        )
        
        write_event = self._create_event("write1", EventType.MEMORY_WRITE, 10, "shared_var", "thread_1")
        
        unlock_event = Event(
            event_id="unlock1",
            event_type=EventType.LOCK_RELEASE,
            location=CodeLocation("test.cpp", 15, 15),
            function_name="func1",
            sync_object="mutex_1",
            thread_id="thread_1"
        )
        
        for event in [lock_event, write_event, unlock_event]:
            graph.add_event(event)
        
        # Add synchronization relations
        graph.add_happen_before_relation(HappenBeforeRelation("lock1", "write1", "synchronization"))
        graph.add_happen_before_relation(HappenBeforeRelation("write1", "unlock1", "synchronization"))
        
        race_conditions = graph.find_race_conditions()
        assert len(race_conditions) == 0
    
    def test_atomic_operations(self):
        """Test that atomic operations don't create race conditions."""
        graph = HappenBeforeGraph()
        
        atomic_read = Event(
            event_id="atomic_read",
            event_type=EventType.ATOMIC_READ,
            location=CodeLocation("test.cpp", 10, 10),
            function_name="func1",
            variable_name="shared_var",
            thread_id="thread_1",
            is_atomic=True
        )
        
        regular_write = self._create_event("regular_write", EventType.MEMORY_WRITE, 20, "shared_var", "thread_2")
        
        graph.add_event(atomic_read)
        graph.add_event(regular_write)
        
        race_conditions = graph.find_race_conditions()
        assert len(race_conditions) == 0


if __name__ == "__main__":
    pytest.main([__file__])
