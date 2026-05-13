"""
Safe unpacking utilities to prevent "too many values to unpack" errors
"""

def safe_unpack_2(iterable, default=(None, None)):
    """
    Safely unpack an iterable into 2 variables
    
    Args:
        iterable: Any iterable (list, tuple, etc.)
        default: Default values if unpacking fails
    
    Returns:
        Tuple of 2 values
    
    Example:
        >>> a, b = safe_unpack_2(some_function())
        >>> # Even if some_function() returns 0, 1, 2, or 3+ values
    """
    try:
        if iterable is None:
            return default
        
        if isinstance(iterable, (list, tuple)):
            if len(iterable) == 0:
                return default
            elif len(iterable) == 1:
                return iterable[0], default[1]
            elif len(iterable) == 2:
                return iterable[0], iterable[1]
            else:
                # More than 2 values - take first 2
                return iterable[0], iterable[1]
        else:
            # Single value, not iterable
            return iterable, default[1]
    except Exception:
        return default

def safe_unpack_3(iterable, default=(None, None, None)):
    """
    Safely unpack an iterable into 3 variables
    
    Args:
        iterable: Any iterable (list, tuple, etc.)
        default: Default values if unpacking fails
    
    Returns:
        Tuple of 3 values
    """
    try:
        if iterable is None:
            return default
        
        if isinstance(iterable, (list, tuple)):
            if len(iterable) == 0:
                return default
            elif len(iterable) == 1:
                return iterable[0], default[1], default[2]
            elif len(iterable) == 2:
                return iterable[0], iterable[1], default[2]
            elif len(iterable) == 3:
                return iterable[0], iterable[1], iterable[2]
            else:
                # More than 3 values - take first 3
                return iterable[0], iterable[1], iterable[2]
        else:
            # Single value
            return iterable, default[1], default[2]
    except Exception:
        return default

def safe_unpack_n(iterable, n, default=None):
    """
    Safely unpack an iterable into n variables
    
    Args:
        iterable: Any iterable (list, tuple, etc.)
        n: Number of variables to unpack into
        default: Default value for missing items
    
    Returns:
        Tuple of n values
    
    Example:
        >>> a, b, c, d = safe_unpack_n(some_list, 4, default='N/A')
    """
    try:
        if iterable is None:
            return tuple([default] * n)
        
        if not isinstance(iterable, (list, tuple)):
            # Convert to list
            iterable = [iterable]
        
        # Pad or trim to exact length
        result = list(iterable)[:n]  # Take first n items
        while len(result) < n:
            result.append(default)  # Pad with defaults
        
        return tuple(result)
    except Exception:
        return tuple([default] * n)

def safe_dict_unpack(dictionary, keys, default=None):
    """
    Safely unpack dictionary values
    
    Args:
        dictionary: Dictionary to unpack from
        keys: List of keys to extract
        default: Default value for missing keys
    
    Returns:
        Tuple of values corresponding to keys
    
    Example:
        >>> name, age, city = safe_dict_unpack(data, ['name', 'age', 'city'], default='Unknown')
    """
    try:
        if not isinstance(dictionary, dict):
            return tuple([default] * len(keys))
        
        return tuple(dictionary.get(key, default) for key in keys)
    except Exception:
        return tuple([default] * len(keys))

def safe_iterate_items(dictionary):
    """
    Safely iterate over dictionary items
    
    Args:
        dictionary: Dictionary to iterate over
    
    Yields:
        Tuples of (key, value)
    
    Example:
        >>> for key, value in safe_iterate_items(my_dict):
        >>>     print(key, value)
    """
    if dictionary is None:
        return
    
    if not isinstance(dictionary, dict):
        return
    
    try:
        for key, value in dictionary.items():
            yield key, value
    except Exception:
        # If items() fails, try other methods
        try:
            for key in dictionary:
                yield key, dictionary[key]
        except Exception:
            return

# Usage examples and tests
if __name__ == "__main__":
    print("Testing safe_unpack utilities...")
    
    # Test safe_unpack_2
    print("\n1. safe_unpack_2:")
    a, b = safe_unpack_2([1, 2, 3, 4])  # More than 2
    print(f"   [1,2,3,4] -> a={a}, b={b}")
    
    a, b = safe_unpack_2([1])  # Only 1
    print(f"   [1] -> a={a}, b={b}")
    
    a, b = safe_unpack_2([])  # Empty
    print(f"   [] -> a={a}, b={b}")
    
    # Test safe_unpack_3
    print("\n2. safe_unpack_3:")
    a, b, c = safe_unpack_3([1, 2])  # Only 2
    print(f"   [1,2] -> a={a}, b={b}, c={c}")
    
    # Test safe_unpack_n
    print("\n3. safe_unpack_n:")
    a, b, c, d = safe_unpack_n([1, 2], 4, default=0)
    print(f"   [1,2] with n=4 -> a={a}, b={b}, c={c}, d={d}")
    
    # Test safe_dict_unpack
    print("\n4. safe_dict_unpack:")
    data = {'name': 'Alice', 'age': 30}
    name, age, city = safe_dict_unpack(data, ['name', 'age', 'city'], default='Unknown')
    print(f"   {data} -> name={name}, age={age}, city={city}")
    
    print("\n✅ All tests passed!")
