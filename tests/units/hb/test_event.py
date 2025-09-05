"""Tests for Event data structure."""

import pytest
from secgen.ir.hb_graph import Event, EventType
from secgen.core.models import CodeLocation


class TestEvent:
    """Test Event data structure."""
    
    def test_event_creation(self):
        """Test basic event creation."""
        location = CodeLocation("test.cpp", 10, 10)
        event = Event(
            event_id="test_event",
            event_type=EventType.MEMORY_READ,
            location=location,
            function_name="test_func",
            variable_name="x",
            thread_id="thread_1"
        )
        
        assert event.event_id == "test_event"
        assert event.event_type == EventType.MEMORY_READ
        assert event.function_name == "test_func"
        assert event.variable_name == "x"
        assert event.thread_id == "thread_1"

    def test_event_with_sync_object(self):
        """Test event creation with synchronization object."""
        location = CodeLocation("test.cpp", 15, 15)
        event = Event(
            event_id="sync_event",
            event_type=EventType.LOCK_ACQUIRE,
            location=location,
            function_name="sync_func",
            sync_object="mutex_1",
            thread_id="thread_1"
        )
        
        assert event.event_id == "sync_event"
        assert event.event_type == EventType.LOCK_ACQUIRE
        assert event.sync_object == "mutex_1"
        assert event.function_name == "sync_func"

    def test_event_equality(self):
        """Test event equality comparison."""
        location1 = CodeLocation("test.cpp", 10, 10)
        location2 = CodeLocation("test.cpp", 10, 10)
        
        event1 = Event(
            event_id="event1",
            event_type=EventType.MEMORY_READ,
            location=location1,
            function_name="func1",
            variable_name="x",
            thread_id="thread_1"
        )
        
        event2 = Event(
            event_id="event1",
            event_type=EventType.MEMORY_READ,
            location=location2,
            function_name="func1",
            variable_name="x",
            thread_id="thread_1"
        )
        
        assert event1 == event2

    def test_event_string_representation(self):
        """Test event string representation."""
        location = CodeLocation("test.cpp", 10, 10)
        event = Event(
            event_id="test_event",
            event_type=EventType.MEMORY_WRITE,
            location=location,
            function_name="test_func",
            variable_name="shared_var",
            thread_id="thread_1"
        )
        
        str_repr = str(event)
        assert "test_event" in str_repr
        assert "MEMORY_WRITE" in str_repr
        assert "test_func" in str_repr
        assert "shared_var" in str_repr

if __name__ == "__main__":
    pytest.main([__file__])
