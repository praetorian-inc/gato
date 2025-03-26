"""
A module for handling recursive extraction and cleanup of compressed files.

Classes:
    RecursiveExtractor: Main class for handling extraction
    CompressionHandler: Internal handler for compression formats
    ExtractionError: Base exception class
    InsufficientSpaceError: Exception for space-related issues

This module supports multiple compression formats including:
- ZIP (.zip)
- RAR (.rar)
- 7-Zip (.7z)
- TAR (.tar, .tar.gz, .tar.bz2, .tgz)
- Gzip (.gz)
- Bzip2 (.bz2)

Example usage:
    from recursive_extractor import RecursiveExtractor

    extractor = RecursiveExtractor()
    extractor.extract("path/to/archive.zip")
    extractor.cleanup()
"""

import os
import zipfile
import tarfile
import py7zr
import rarfile
import gzip
import bz2
import shutil
import logging
import psutil
from pathlib import Path
from typing import Optional, Set
from dataclasses import dataclass
from tqdm import tqdm

logger = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Base exception for extraction errors."""
    pass


class InsufficientSpaceError(ExtractionError):
    """Raised when there isn't enough disk space for extraction."""
    pass


@dataclass
class ExtractionStats:
    """Statistics about the extraction process."""
    total_files: int = 0
    processed_files: int = 0
    failed_files: int = 0
    total_size: int = 0
    extracted_size: int = 0


class CompressionHandler:
    """Internal handler for different compression formats."""

    def __init__(self):
        self.logger = logger
        self.supported_extensions = {
            '.zip': self._handle_zip,
            '.rar': self._handle_rar,
            '.7z': self._handle_7z,
            '.tar': self._handle_tar,
            '.gz': self._handle_gz,
            '.bz2': self._handle_bz2,
            '.tar.gz': self._handle_tar,
            '.tar.bz2': self._handle_tar,
            '.tgz': self._handle_tar
        }

    def _cleanup_partial(self, path: str) -> None:
        """Clean up partially extracted files after a failure."""
        try:
            if os.path.exists(path):
                shutil.rmtree(path)
                self.logger.debug(f"Cleaned up partial extraction at {path}")
        except Exception as e:
            self.logger.error(f"Failed to clean up partial extraction at {path}: {e}")

    def check_space(self, file_path: str, extract_path: str) -> None:
        """Check if there's enough space for extraction."""
        try:
            file_size = os.path.getsize(file_path)
            needed_space = file_size * 2
            free_space = psutil.disk_usage(os.path.dirname(extract_path)).free

            if free_space < needed_space:
                raise InsufficientSpaceError(
                    f"Not enough space for extraction. Need {needed_space // 1024 // 1024}MB, "
                    f"have {free_space // 1024 // 1024}MB free"
                )
        except Exception as e:
            self.logger.error(f"Error checking space: {e}")
            raise

    def is_compressed_file(self, filename: str) -> bool:
        """Check if a file is a supported compressed archive."""
        file_path = Path(filename)
        if str(file_path).endswith(('.tar.gz', '.tar.bz2', '.tgz')):
            return True
        return file_path.suffix.lower() in self.supported_extensions

    def _handle_zip(self, file_path: str, extract_path: str) -> bool:
        """Handle ZIP files with progress bar."""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                total_size = sum(info.file_size for info in zip_ref.filelist)
                with tqdm(total=total_size, unit='B', unit_scale=True, desc="Extracting ZIP", disable=True) as pbar:
                    for member in zip_ref.filelist:
                        zip_ref.extract(member, extract_path)
                        pbar.update(member.file_size)
            return True
        except zipfile.BadZipFile:
            self.logger.error(f"Invalid or corrupted ZIP file: {file_path}")
            return False
        except Exception as e:
            self.logger.error(f"Error extracting ZIP file {file_path}: {e}")
            return False

    def _handle_rar(self, file_path: str, extract_path: str) -> bool:
        """Handle RAR files."""
        try:
            # Create all parent directories
            os.makedirs(extract_path, exist_ok=True)

            with rarfile.RarFile(file_path, 'r') as rar_ref:
                rar_ref.extractall(extract_path)
            return True
        except rarfile.BadRarFile:
            self.logger.error(f"Invalid or corrupted RAR file: {file_path}")
            return False
        except Exception as e:
            self.logger.error(f"Error extracting RAR file {file_path}: {e}")
            return False

    def _handle_7z(self, file_path: str, extract_path: str) -> bool:
        """Handle 7z files."""
        try:
            with py7zr.SevenZipFile(file_path, 'r') as sz_ref:
                sz_ref.extractall(extract_path)
            return True
        except py7zr.Bad7zFile:
            self.logger.error(f"Invalid or corrupted 7z file: {file_path}")
            return False
        except Exception as e:
            self.logger.error(f"Error extracting 7z file {file_path}: {e}")
            return False

    def _handle_tar(self, file_path: str, extract_path: str) -> bool:
        """Handle TAR files (including compressed variants)."""
        try:
            with tarfile.open(file_path, 'r:*') as tar_ref:
                def is_within_directory(directory: str, target: str) -> bool:
                    abs_directory = os.path.abspath(directory)
                    abs_target = os.path.abspath(target)
                    prefix = os.path.commonprefix([abs_directory, abs_target])
                    return prefix == abs_directory

                def safe_extract(tar: tarfile.TarFile, path: str) -> None:
                    for member in tar.getmembers():
                        member_path = os.path.join(path, member.name)
                        if not is_within_directory(path, member_path):
                            self.logger.debug(f"Attempted path traversal in tar file: {member.name}")
                            continue
                        try:
                            tar.extract(member, path)
                        except PermissionError:
                            # Just log and continue if we hit permission issues
                            self.logger.warning(f"Permission error extracting {member.name}, skipping")
                            continue

                safe_extract(tar_ref, extract_path)
            return True
        except tarfile.ReadError:
            self.logger.error(f"Invalid or corrupted TAR file: {file_path}")
            return False
        except Exception as e:
            self.logger.error(f"Error extracting TAR file {file_path}: {e}")
            return False

    def _handle_gz(self, file_path: str, extract_path: str) -> bool:
        """Handle GZ files."""
        try:
            # Create all parent directories
            os.makedirs(extract_path, exist_ok=True)

            # Get the output path
            output_path = os.path.join(extract_path, Path(file_path).stem)

            # Extract the file
            with gzip.open(file_path, 'rb') as gz_ref:
                with open(output_path, 'wb') as out_ref:
                    shutil.copyfileobj(gz_ref, out_ref)
            return True
        except Exception as e:
            self.logger.error(f"Error extracting GZ file {file_path}: {e}")
            return False

    def _handle_bz2(self, file_path: str, extract_path: str) -> bool:
        """Handle BZ2 files."""
        try:
            # Create all parent directories
            os.makedirs(extract_path, exist_ok=True)

            output_path = os.path.join(extract_path, Path(file_path).stem)
            with bz2.open(file_path, 'rb') as bz2_ref:
                with open(output_path, 'wb') as out_ref:
                    shutil.copyfileobj(bz2_ref, out_ref)
            return True
        except Exception as e:
            self.logger.error(f"Error extracting BZ2 file {file_path}: {e}")
            return False

    def extract_file(self, file_path: str, extract_path: str) -> bool:
        """Extract a compressed file based on its extension."""
        try:

            # adding this in to try and resolve error with checking space of nonexistent dirs; remove if it causes errors
            os.makedirs(extract_path, exist_ok=True)

            self.check_space(file_path, extract_path)

            file_path_lower = str(file_path).lower()

            if file_path_lower.endswith(('.tar.gz', '.tar.bz2', '.tgz')):
                return self._handle_tar(file_path, extract_path)

            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.supported_extensions:
                return self.supported_extensions[file_ext](file_path, extract_path)

            self.logger.warning(f"Unsupported file format: {file_path}")
            return False

        except InsufficientSpaceError as e:
            self.logger.error(str(e))
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error extracting {file_path}: {e}")
            return False


class RecursiveExtractor:
    """
    Main class for handling recursive extraction of compressed files.

    Attributes:
        logger (logging.Logger): Logger instance for tracking operations
        processed_files (Set[str]): Set of already processed files
        extraction_path (str): Path where files are being extracted
    """

    def __init__(self):
        """
        Initialize the extractor.

        Args:
            log_file (str): Path to the log file
            log_level (int): Logging level (e.g., logging.INFO)
        """
        self.logger = logger

        # Add handlers if they don't exist
        if not self.logger.handlers:

            # Console handler
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
            self.logger.addHandler(ch)

        self.handler = CompressionHandler()
        self.processed_files: Set[str] = set()
        self.extraction_path: Optional[str] = None

    def extract(self,
                file_path: str,
                custom_extract_path: Optional[str] = None,
                max_workers: int = 1) -> bool:
        """
        Extract a compressed file and all nested compressed files within it.

        Args:
            file_path (str): Path to the compressed file
            custom_extract_path (str, optional): Custom extraction path

        Returns:
            bool: True if extraction was successful, False otherwise

        Raises:
            ExtractionError: If there's an error during extraction
        """
        try:
            if not os.path.exists(file_path):
                raise ExtractionError("The specified file does not exist")

            if not os.path.isfile(file_path):
                raise ExtractionError("The specified path is not a file")

            if not self.handler.is_compressed_file(file_path):
                raise ExtractionError("The specified file is not a supported compressed file")

            self.extraction_path = custom_extract_path or f"{file_path}_extracted"

            # Extract the initial compressed file
            if not self.handler.extract_file(file_path, self.extraction_path):
                raise ExtractionError("Failed to extract initial compressed file")

            self._extract_recursive(self.extraction_path)
            self.logger.debug("Extraction process completed successfully!")
            return True

        except KeyboardInterrupt:
            self.logger.warning("\nExtraction interrupted by user")
            if self.extraction_path:
                self.cleanup()
            return False
        except Exception as e:
            self.logger.error(f"Extraction failed: {str(e)}")
            if self.extraction_path:
                self.cleanup()
            return False

    def _extract_recursive(self, current_path: str) -> None:
        """Internal method for recursive extraction."""
        if not os.path.exists(current_path):
            self.logger.error(f"Path does not exist: {current_path}")
            return

        for root, _, files in os.walk(current_path):
            for file in files:
                file_path = os.path.join(root, file)

                if file_path in self.processed_files:
                    continue

                if self.handler.is_compressed_file(file_path):
                    self.logger.debug(f"Processing compressed file: {file_path}")
                    new_extract_path = os.path.join(
                        os.path.dirname(file_path),
                        f"{Path(file).stem}_extracted"
                    )

                    if self.handler.extract_file(file_path, new_extract_path):
                        self.processed_files.add(file_path)
                        self._extract_recursive(new_extract_path)
                        try:
                            os.remove(file_path)
                            self.logger.debug(f"Removed compressed file: {file_path}")
                        except Exception as e:
                            self.logger.warning(f"Failed to remove compressed file {file_path}: {e}")
                    else:
                        self.logger.warning(
                            f"Skipping further processing of {file_path} due to extraction failure"
                        )

    def cleanup(self) -> bool:
        """
        Clean up the extracted files.

        Returns:
            bool: True if cleanup was successful, False otherwise
        """

        if not self.extraction_path or not os.path.exists(self.extraction_path):
            return True

        try:
            shutil.rmtree(self.extraction_path)
            return True
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
            return False

    def get_supported_formats(self) -> Set[str]:
        """Get the list of supported compression formats."""
        return set(self.handler.supported_extensions.keys())
