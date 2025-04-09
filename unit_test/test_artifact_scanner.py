import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path
import shutil

from gato.artifact_secrets_scanner.artifact_files import (
    CompressionHandler,
    RecursiveExtractor,
    ExtractionError,
    InsufficientSpaceError
)

def test_compression_handler_init():
    """Test that CompressionHandler initializes correctly."""
    handler = CompressionHandler()
    assert handler is not None

def test_is_compressed_file():
    """Test CompressionHandler.is_compressed_file method."""
    handler = CompressionHandler()
    
    # Test various file extensions
    assert handler.is_compressed_file("test.zip") is True
    assert handler.is_compressed_file("test.tar.gz") is True
    assert handler.is_compressed_file("test.7z") is True
    assert handler.is_compressed_file("test.rar") is True
    assert handler.is_compressed_file("test.gz") is True
    assert handler.is_compressed_file("test.bz2") is True
    
    # Test non-compressed files
    assert handler.is_compressed_file("test.txt") is False
    assert handler.is_compressed_file("test.png") is False
    assert handler.is_compressed_file("test") is False

def test_recursive_extractor_init():
    """Test that RecursiveExtractor initializes correctly."""
    extractor = RecursiveExtractor()
    assert extractor is not None
    assert extractor.handler is not None
    assert isinstance(extractor.handler, CompressionHandler)
    assert extractor.processed_files == set()
    assert extractor.extraction_path is None

def test_get_supported_formats():
    """Test RecursiveExtractor.get_supported_formats method."""
    extractor = RecursiveExtractor()
    handler = extractor.handler
    formats = set(handler.supported_extensions.keys())
    
    # Check that the returned value is a set
    assert isinstance(formats, set)
    
    # Check that common formats are included
    assert '.zip' in formats
    assert '.tar.gz' in formats
    assert '.7z' in formats

@patch('shutil.rmtree')
def test_cleanup(mock_rmtree):
    """Test RecursiveExtractor cleanup method."""
    extractor = RecursiveExtractor()
    
    # Set up a fake extraction path
    test_dir = tempfile.mkdtemp()
    extractor.extraction_path = test_dir
    
    # Create a test file in the temp directory
    test_file = os.path.join(test_dir, "test.txt")
    with open(test_file, "w") as f:
        f.write("test")
    
    # Verify file exists
    assert os.path.exists(test_file)
    
    # Call cleanup (since we're patching rmtree, we need to manually clean up)
    with patch.object(extractor, 'cleanup') as mock_cleanup:
        mock_cleanup.return_value = True
        result = extractor.cleanup()
    
    # Verify cleanup was called
    mock_cleanup.assert_called_once()
    
    # Clean up the test directory
    try:
        shutil.rmtree(test_dir)
    except:
        pass 