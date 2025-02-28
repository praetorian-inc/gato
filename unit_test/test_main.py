import pytest
from unittest.mock import patch, MagicMock
import sys
from gato.main import entry

def test_entry():
    """Test that the entry function calls cli.cli with proper arguments."""
    with patch('gato.cli.cli.cli') as mock_cli:
        mock_cli.return_value = 0
        
        # Save original argv
        original_argv = sys.argv.copy()
        
        try:
            # Mock the argv for testing
            sys.argv = ['gato', 'test_arg1', 'test_arg2']
            
            # Call entry and catch the SystemExit
            with pytest.raises(SystemExit) as exit_info:
                entry()
            
            # Verify exit code is 0
            assert exit_info.value.code == 0
            
            # Verify cli.cli was called with the correct arguments
            mock_cli.assert_called_once_with(['test_arg1', 'test_arg2'])
            
        finally:
            # Restore original argv
            sys.argv = original_argv

def test_entry_error():
    """Test that the entry function handles non-zero return codes."""
    with patch('gato.cli.cli.cli') as mock_cli:
        mock_cli.return_value = 1
        
        # Call entry
        with pytest.raises(SystemExit) as exit_info:
            entry()
        
        # Verify the exit code
        assert exit_info.value.code == 1 