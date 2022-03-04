def checkHashAge(hashList=None, **kwargs):
    """
    Args:
        hashList (CEF type: hash)
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.grab
        *.hash
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import datetime
    
    outputs = {'hash': [],'grab': []}
    
    for hash in hashList:
        outputs['hash'].append(hash)
        success, message, matched = phantom.get_list(list_name='virus_total_cache', values=hash)
        phantom.debug('phantom.check_list results: success: {}, message: {}, matched_row_count: {}'.format(success, message, matched))
        if matched.get('matches'):
            current_time = datetime.datetime.now()
            seven_days = datetime.timedelta(days=7)
            seven_days_ago = current_time - seven_days
            lookup_date = datetime.datetime.strptime(matched.get('matches')[0].get('value')[1], "%Y-%m-%d %H:%M:%S.%f")
    
            if lookup_date > seven_days_ago:
                outputs['grab'].append('True')
            else:
                outputs['grab'].append('False')
        else:
            outputs['grab'].append('False')
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
