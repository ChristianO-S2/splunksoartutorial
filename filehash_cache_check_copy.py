"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_field' block
    check_field(container=container)

    return

def check_field(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_field() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="check_field:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_splunksoartutorial_checkHashAge_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def check_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_list() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:check_field:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_list__inList = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import datetime
    
    output = {'hash': [],'grab': []}
    
    for hash in filtered_artifacts_item_1_0:
        output['hash'].append(hash)
        success, message, matched = phantom.get_list(list_name='virus_total_cache', values=hash)
        phantom.debug('phantom.check_list results: success: {}, message: {}, matched_row_count: {}'.format(success, message, matched))
        if matched.get('matches'):
            current_time = datetime.datetime.now()
            seven_days = datetime.timedelta(days=7)
            seven_days_ago = current_time - seven_days
            lookup_date = datetime.datetime.strptime(matched.get('matches')[0].get('value')[1], "%Y-%m-%d %H:%M:%S.%f")
    
            if lookup_date > seven_days_ago:
                output['grab'].append('True')
            else:
                output['grab'].append('False')
        else:
            output['grab'].append('False')# Write your custom code here...
    
    check_list__inList = output
    phantom.debug(output)
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_list:inList', value=json.dumps(check_list__inList))
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_list:custom_function:inList.*.grab", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    return

def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation() called')

    # collect data for 'file_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:check_field:condition_1:artifact:*.cef.fileHash', 'filtered-data:check_field:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=update_cache, name="file_reputation")

    return

def grab_from_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('grab_from_cache() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:check_field:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    grab_from_cache__malicious_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    success, message, matches = phantom.get_list(list_name='virus_total_cache', values=filtered_artifacts_item_1_0[0])
    if matches.get('matches'):
        malicious_count = matches.get('matches')[0].get('value')[2]
        success_2, message_2 = phantom.delete_from_list(list_name="virus_total_cache", value=filtered_artifacts_item_1_0[0], remove_row=True)
        success_1, message_1 = phantom.add_list(list_name="virus_total_cache", values=[matches.get('matches')[0].get('value')[0], matches.get('matches')[0].get('value')[1], matches.get('matches')[0].get('value')[2], int(matches.get('matches')[0].get('value')[3]) + 1])
        
    phantom.debug('phantom.get_list results: success: {}, message: {}, malicious_count: {}'.format(success, message, malicious_count))# Write your custom code here...
    grab_from_cache__malicious_count = malicious_count
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='grab_from_cache:malicious_count', value=json.dumps(grab_from_cache__malicious_count))
    decision_3(container=container)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["grab_from_cache:custom_function:malicious_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        severity_high_pin_cached(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    severity_low_pin_cached(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def severity_high_pin_cached(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('severity_high_pin_cached() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.set_severity(container, "High")
    phantom.pin(container=container, pin_style='red', data="malicious file found", pin_type="card")# Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def severity_low_pin_cached(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('severity_low_pin_cached() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.set_severity(container, "Low")
    phantom.pin(container=container, pin_style='blue', data="file is known good", pin_type="card")# Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation:action_result.summary.malicious", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        severity_high_pin_live(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    severity_low_pin_live(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def severity_high_pin_live(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('severity_high_pin_live() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.set_severity(container, "High")
    phantom.pin(container=container, pin_style='red', data="malicious file found", pin_type="card")# Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def severity_low_pin_live(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('severity_low_pin_live() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.set_severity(container, "Low")
    phantom.pin(container=container, pin_style='blue', data="file is known good", pin_type="card")# Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def update_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_cache() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation:action_result.summary.malicious'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:check_field:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import datetime
    
    success_1, message_1, matches = phantom.get_list(list_name='virus_total_cache', values=filtered_artifacts_item_1_0[0])
    
    if matches.get('matches'):
        success_3, message_3 = phantom.delete_from_list(list_name="virus_total_cache", value=filtered_artifacts_item_1_0[0], remove_row=True)
        success, message = phantom.add_list(list_name="virus_total_cache", values=[matches.get('matches')[0].get('value')[0], datetime.datetime.now(), results_item_1_0[0], int(matches.get('matches')[0].get('value')[3]) + 1])
    else:
        success_2, message_2 = phantom.add_list(list_name="virus_total_cache", values=[filtered_artifacts_item_1_0[0], datetime.datetime.now(), results_item_1_0[0], 1])# Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################
    decision_4(container=container)

    return

def cf_splunksoartutorial_checkHashAge_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_splunksoartutorial_checkHashAge_1() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:check_field:condition_1:artifact:*.cef.fileHash'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
        parameters.append({
            'hashList': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "splunksoartutorial/checkHashAge", returns the custom_function_run_id
    phantom.custom_function(custom_function='splunksoartutorial/checkHashAge', parameters=parameters, name='cf_splunksoartutorial_checkHashAge_1')

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return