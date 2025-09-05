"""Shared test fixtures and utilities for happen-before analysis tests."""

import pytest
from secgen.ir.hb_graph import Event, EventType, SynchronizationType
from secgen.core.models import FunctionInfo, CodeLocation


@pytest.fixture
def sample_code_location():
    """Create a sample code location for testing."""
    return CodeLocation("test.cpp", 10, 10)


@pytest.fixture
def sample_memory_event(sample_code_location):
    """Create a sample memory event for testing."""
    return Event(
        event_id="test_event",
        event_type=EventType.MEMORY_READ,
        location=sample_code_location,
        function_name="test_func",
        variable_name="x",
        thread_id="thread_1"
    )


@pytest.fixture
def sample_write_event(sample_code_location):
    """Create a sample write event for testing."""
    return Event(
        event_id="write_event",
        event_type=EventType.MEMORY_WRITE,
        location=sample_code_location,
        function_name="writer_func",
        variable_name="shared_var",
        thread_id="thread_1"
    )


@pytest.fixture
def sample_lock_event(sample_code_location):
    """Create a sample lock event for testing."""
    return Event(
        event_id="lock_event",
        event_type=EventType.LOCK_ACQUIRE,
        location=sample_code_location,
        function_name="lock_func",
        sync_object="mutex_1",
        sync_type=SynchronizationType.MUTEX,
        thread_id="thread_1"
    )


@pytest.fixture
def sample_functions():
    """Create sample function info for testing."""
    return {
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
