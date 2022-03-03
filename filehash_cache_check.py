"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def update_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_custom_list() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    action_results_data_0 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.malicious', 'file_reputation_1:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in filtered_artifacts_data_0:
        for item1 in action_results_data_0:
            parameters.append({
                'hash': item0[0],
                'malicious_count': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/listUpdater", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/listUpdater', parameters=parameters, name='update_custom_list', callback=decision_4)

    return

def check_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_list() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_list__inList = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import datetime
    
    current_time = datetime.datetime.now()
    seven_days = datetime.timedelta(days=7)
    seven_days_ago = current_time - seven_days
    
    success, message, matched = phantom.get_list(list_name='virus_total_cache', values=filtered_artifacts_item_1_0[0])
    if success:
        lookup_date = datetime.datetime.strptime(matched.get('matches')[0].get('value')[1], "%Y-%m-%d %H:%M:%S.%f")
    
        if lookup_date > seven_days_ago:
            grab = True
        else:
            grab = False# Write your custom code here...
    
    phantom.debug(grab)
    phantom.debug('phantom.check_list results: success: {}, message: {}, matched_row_count: {}'.format(success, message, matched))
    check_list__inList = grab
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

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_list:custom_function:inList", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        grab_from_cache(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=update_custom_list, name="file_reputation_1")

    return

def grab_from_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('grab_from_cache() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    grab_from_cache__malicious_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    success, message, matches = phantom.get_list(list_name='virus_total_cache', values=filtered_artifacts_item_1_0[0])
    malicious_count = matches.get('matches')[0].get('value')[2]
    phantom.debug('phantom.get_list results: success: {}, message: {}, malicious_count: {}'.format(success, message, malicious_count))# Write your custom code here...
    grab_from_cache__malicious_count = malicious_count
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
    phantom.pin(container=container, pin_style='red', data="malicious hash found", pin_type="card")# Write your custom code here...

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
    phantom.pin(container=container, pin_style='blue', data="no malicious hash", pin_type="card")# Write your custom code here...

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
            ["file_reputation_1:action_result.summary.malicious", ">", 0],
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
    phantom.pin(container=container, pin_style='red', data="malicious hash found", pin_type="card")# Write your custom code here...

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
    phantom.pin(container=container, pin_style='blue', data="no malicious hash", pin_type="card")# Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

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