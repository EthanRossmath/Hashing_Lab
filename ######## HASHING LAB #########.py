######## HASHING LAB #########
##############################
######### ETHAN ROSS #########


### URL FORMATTING ###

def url_format(data: bytes) -> str:
    """
    Convert a bytes sequence to its URL-encoded representation by percent-encoding each byte.

    Each byte in the input is formatted as a two-digit hexadecimal number,
    prefixed with '%', as commonly used in URL encoding.

    Args:
        data (bytes): The input data to encode.

    Returns:
        str: A string where each byte of `data` is represented as '%XX',
             with XX being the lowercase hexadecimal value of the byte.

    Example:
        >>> url_format(b'Hello!')
        '%48%65%6c%6c%6f%21'
    """
    string = data.hex()
    return '%'.join(string[i:i+2] for i in range(-2, len(string), 2))


### HASHING ALGORITHM ###
def compute_hash(message, output_format = 'bytes', algorithm = 'md5'):
    '''
    
    Parameters
    ----------
    algorithm : str
        Must be one of the following algorithms: 
	    1. 'md5'
	    2. 'sha256'
	    3. 'sha512'
	
	    Otherwise throws an error. 
    message : bytes (or bytes-like object)
        Encoded message to be hashed with the given algorithm. 
	output_format : str
		Must be one of the following: 
		i. 'bytes'
	    ii. 'hex'
		iii. base64

		Otherwise throws an error
		
    Returns
    -------
	The hash digest of message, using the given algorithm, in the given format. If 'bytes', will return a bytes object. If 'hex' or 'base64' will return a string of the given encoding. 
    '''
    # import necessary libraries
    import hashlib
    import base64

    valid_algorithms = ['md5', 'sha256', 'sha512']
    valid_formats = ['bytes', 'hex', 'base64']
    if algorithm not in valid_algorithms:
        return ValueError('Algorithm must be one of md5, sha256, or sha512')
    
    if output_format not in valid_formats:
        return ValueError('Output format must be one of bytes, hex, or base64')

    if algorithm == 'md5':
        m_md5 = hashlib.md5(message)

        if output_format == 'bytes':
            return m_md5.digest()
        if output_format == 'hex':
            return m_md5.hexdigest()
        else:
            return base64.b64encode(m_md5.digest())

    elif algorithm == 'sha256':
        m_sha256 = hashlib.sha256(message)

        if output_format == 'bytes':
            return m_sha256.digest()
        if output_format == 'hex':
            return m_sha256.hexdigest()
        else:
            return base64.b64encode(m_sha256.digest())
    
    else:
        m_sha512 = hashlib.sha512(message)

        if output_format == 'bytes':
            return m_sha512.digest()
        if output_format == 'hex':
            return m_sha512.hexdigest()
        else:
            return base64.b64encode(m_sha512.digest())
        
### PADDING COMPUTING ###

def compute_padding( algorithm: str = 'md5',
         output_format: str = 'bytes', 
         message: bytes = None,
        ):
    """
    Parameters
    ----------
    algorithm : str
        One of: 'md5', 'sha256', 'sha512'
    message : bytes
        Data to hash. Required.
    output_format : str
        One of: 'bytes', 'hex', 'base64'
    
    Returns
    -------
    bytes or str
        The padding that the given algorithm adds to the message before processing. To be used in implementation of the length extension attack. 
    """