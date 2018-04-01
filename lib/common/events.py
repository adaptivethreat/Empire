"""
Event handling system
Every "major" event in Empire (loosely defined as everything you'd want to
go into a report) is logged to the database. This file contains functions
which help manage those events - logging them, fetching them, etc.
"""

import json

from pydispatch import dispatcher

#from lib.common import db # used in the disabled TODO below

################################################################################
# Helper functions for logging common events
################################################################################

def agent_rename(old_name, new_name):
    """
    Helper function for reporting agent name changes.

    old_name - agent's old name
    new_name - what the agent is being renamed to
    """
    # make sure to include new_name in there so it will persist if the agent
    # is renamed again - that way we can still trace the trail back if needed
    message = "[*] Agent {} has been renamed to {}".format(old_name, new_name)
    signal = json.dumps({
        'print': False,
        'message': message,
        'old_name': old_name,
        'new_name': new_name,
        'event_type' : 'rename'
    })
    # signal twice, once for each name (that way, if you search by sender,
    # the last thing in the old agent and the first thing in the new is that
    # it has been renamed)
    dispatcher.send(signal, sender="agents/{}".format(old_name))
    dispatcher.send(signal, sender="agents/{}".format(new_name))

    # TODO rename all events left over using agent's old name?
    # in order to handle "agents/<name>" as well as "agents/<name>/stuff"
    # we'll need to query, iterate the list to build replacements, then send
    # a bunch of updates... kind of a pain

    #cur = db.cursor()
    #cur.execute("UPDATE reporting SET name=? WHERE name REGEXP ?", [new_name, old_sender])
    #cur.close()

def log_event(cur, name, event_type, message, timestamp, task_id=None):
    """
    Log arbitrary events

    cur        - a database connection object (such as that returned from
                 `get_db_connection()`)
    name       - the sender string from the dispatched event
    event_type - the category of the event - agent_result, agent_task,
                 agent_rename, etc. Ideally a succinct description of what the
                 event actually is.
    message    - the body of the event, WHICH MUST BE JSON, describing any
                 pertinent details of the event
    timestamp  - when the event occurred
    task_id    - the ID of the task this event is in relation to. Enables quick
                 queries of an agent's task and its result together.
    """
    cur.execute(
        "INSERT INTO reporting (name, event_type, message, time_stamp, taskID) VALUES (?,?,?,?,?)",
        (
            name,
            event_type,
            message,
            timestamp,
            task_id
        )
    )
