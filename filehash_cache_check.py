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
        custom_function_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_local_listUpdater_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_listUpdater_1() called')
    
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
    phantom.custom_function(custom_function='local/listUpdater', parameters=parameters, name='cf_local_listUpdater_1')

    return

def custom_function_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_1() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    custom_function_1__inList = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    success, message, matched_row_count = phantom.check_list(list_name='virus_total_cache', value=filtered_artifacts_item_1_0[0])# Write your custom code here...
    phantom.debug('phantom.check_list results: success: {}, message: {}, matched_row_count: {}'.format(success, message, matched_row_count))
    custom_function_1__inList = success
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_1:inList', value=json.dumps(custom_function_1__inList))
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["custom_function_1:custom_function:inList", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        custom_function_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=cf_local_listUpdater_1, name="file_reputation_1")

    return

def cf_local_getList_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_getList_1() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
        parameters.append({
            'hash': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/getList", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/getList', parameters=parameters, name='cf_local_getList_1')

    return

def custom_function_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_2() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    custom_function_2__malicious_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    success, message, matches = phantom.get_list(list_name='virus_total_cache', values=filtered_artifacts_item_1_0[0])
    malicious_count = matches.get('matches')[0].get('value')[2]
    phantom.debug('phantom.get_list results: success: {}, message: {}, malicious_count: {}'.format(success, message, malicious_count))# Write your custom code here...
    custom_function_2__malicious_count = malicious_count
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ####################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_2:malicious_count', value=json.dumps(custom_function_2__malicious_count))
    decision_3(container=container)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["custom_function_2:custom_function:malicious_count", ">=", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_severity_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container=container, severity="High")

    container = phantom.get_container(container.get('id', None))

    return

def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_2() called')

    phantom.set_severity(container=container, severity="Low")

    container = phantom.get_container(container.get('id', None))

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