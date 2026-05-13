import chardet
import logging
from typing import Optional, Union

logger = logging.getLogger(__name__)

def safe_decode(content: bytes, default_encoding: str = 'utf-8') -> str:
    """
    Safely decode bytes content with automatic encoding detection.
    
    Args:
        content (bytes): The bytes content to decode
        default_encoding (str): Default encoding to try first
        
    Returns:
        str: Decoded string content
    """
    if not isinstance(content, bytes):
        return str(content)
    
    # Try default encoding first
    try:
        return content.decode(default_encoding)
    except UnicodeDecodeError:
        pass
    
    # Try to detect encoding
    try:
        detected = chardet.detect(content)
        if detected and detected['confidence'] > 0.7:
            detected_encoding = detected['encoding']
            try:
                return content.decode(detected_encoding)
            except UnicodeDecodeError:
                pass
    except Exception as e:
        logger.warning(f"Encoding detection failed: {e}")
    
    # Try common encodings
    common_encodings = ['latin-1', 'cp1252', 'iso-8859-1', 'windows-1252']
    for encoding in common_encodings:
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    
    # Final fallback with error handling
    try:
        return content.decode(default_encoding, errors='ignore')
    except Exception as e:
        logger.error(f"All decoding attempts failed: {e}")
        return content.decode('latin-1', errors='ignore')

def safe_encode(content: str, encoding: str = 'utf-8') -> bytes:
    """
    Safely encode string content to bytes.
    
    Args:
        content (str): The string content to encode
        encoding (str): Encoding to use
        
    Returns:
        bytes: Encoded bytes content
    """
    if isinstance(content, bytes):
        return content
    
    try:
        return content.encode(encoding)
    except UnicodeEncodeError:
        try:
            return content.encode('latin-1', errors='ignore')
        except Exception as e:
            logger.error(f"Encoding failed: {e}")
            return content.encode('utf-8', errors='ignore')

def fix_file_encoding(file_path: str, output_path: Optional[str] = None) -> bool:
    """
    Fix encoding issues in a file by re-encoding it properly.
    
    Args:
        file_path (str): Path to the file to fix
        output_path (str, optional): Output path for fixed file. If None, overwrites original
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Read file in binary mode
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Decode content safely
        decoded_content = safe_decode(content)
        
        # Write back with proper encoding
        output_file = output_path or file_path
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(decoded_content)
        
        logger.info(f"Successfully fixed encoding for {file_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to fix encoding for {file_path}: {e}")
        return False

def validate_encoding(content: Union[str, bytes]) -> bool:
    """
    Validate if content can be properly encoded/decoded.
    
    Args:
        content: Content to validate
        
    Returns:
        bool: True if content is valid, False otherwise
    """
    try:
        if isinstance(content, bytes):
            content.decode('utf-8')
        else:
            content.encode('utf-8')
        return True
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
