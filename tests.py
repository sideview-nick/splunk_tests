import sys
import os
#import json
#import csv
import re
import unittest
#import base64
import time
import splunk
import splunk.auth
import traceback


#SPLUNK_HOME = os.environ["SPLUNK_HOME"]

# accept auth from a filename named in the environent.
authfilename = os.environ.get('SIDEVIEWTEST_AUTHFILE', None)

if sys.stdin.isatty() and not authfilename:
    print("you need to call this like so:")
    print("> splunk cmd python unit_tests.py < auth.txt")
    print("where the auth.txt file has 4 lines, each of which look like")
    print("\"theophrastus:hunter2\"")
    print("and the first is an admin user but who lacks admin_all_objects")
    print("the second user is a admin user WITH that capability, the next is")
    print("a power user, the last is a user user.")
    print("Alternatively, put SIDEVIEWTEST_AUTHFILE in the environment, for example..")
    print(" export SIDEVIEWTEST_AUTHFILE=/path/to/auth.txt")

    sys.exit()

authdata_f = open(authfilename, "r") if authfilename else sys.stdin

session_keys = []
usernames = []
for line in authdata_f:
    try:
        username, password = line.rstrip().split(":")
        session_key = splunk.auth.getSessionKey(username=username, password=password)
        session_keys.append(session_key)
        usernames.append(username)
    except splunk.AuthenticationFailed as e:
        sys.exit("it seems we have the wrong password for %s and that it is not --%s--" % (username, password))

if authfilename:
    authdata_f.close()

session_key = session_keys[0]
admin_session_key = session_keys[0]
uber_admin_session_key = session_keys[1]
power_session_key = session_keys[2]
user_session_key = session_keys[3]
admin1_username = usernames[0]
admin2_username = usernames[1]
power_username = usernames[2]
user_username = usernames[3]


#def run_search(search, session_key, app_name, earliest=None, latest=None):
#    uri = "/servicesNS/-/%s/search/jobs/" % app_name
#    postargs = {
#        "search": search,
#        "exec_mode": "oneshot",
#        "output_mode": "json"
#    }
#    if earliest:
#        postArgs["earliest_time"] = earliest
#    if latest:
#        postArgs["latest_time"] = latest
#
#    getargs = {}
#
#    return splunk.rest.simpleRequest(
#        uri, postargs=postargs, getargs=getargs, raiseAllErrors=True,
#        sessionKey=session_key
#    )

class InstrumentedTestCase(unittest.TestCase):
    def setUp(self):
        self._started_at = time.time()
        #print('{} started'.format(self.id()))
    def tearDown(self):
        elapsed = time.time() - self._started_at
        if elapsed > 5:
            print('{} ({}s)'.format(self.id(), round(elapsed, 2)))



class TestParserEndpoint(InstrumentedTestCase):

    def test_parser_endpoint_smoke(self):
        getargs = {
            "q": "search foo bar"
        }
        uri = "/servicesNS/nobody/search/search/parser"
        response, content = splunk.rest.simpleRequest(uri, sessionKey=admin_session_key, method='GET', getargs=getargs, raiseAllErrors=True)
        self.assertEqual(response["status"], "200", "should get an answer back")
        #print(content)

        

    
class CoreSplunkTestCase(InstrumentedTestCase):
    public_name = "unimplemented"
    private_name = "unimplemented"
    def tearDown(self):
        combinations = [
            [admin1_username, self.public_name, admin_session_key],
            [admin2_username, self.public_name, uber_admin_session_key],
            [admin1_username, self.private_name, admin_session_key],
            [admin2_username, self.private_name, uber_admin_session_key],
            [user_username, self.private_name, user_session_key],
            ["nobody", self.public_name, uber_admin_session_key],
            ["nobody", self.private_name, uber_admin_session_key]
        ]

        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            db_name = "%s-%s" % (self.private_name, usernames[i])
            combinations.extend([[user, db_name, key]])
            combinations.extend([["nobody", db_name, key]])

        for c in combinations:
            try:
                self.delete_thing(c[0], c[1], c[2])
                #print("successfully deleted dashboard %s %s %s" % tuple(c))
            except splunk.ResourceNotFound as e:
                pass

        super(CoreSplunkTestCase, self).tearDown()

    def get_post_args(self, name=False):
        return {}

    def get_writable_flag(self, xmlStr):
        if sys.version_info.major >= 3:
            xmlStr = str(xmlStr, "utf-8")
        match = re.search(r'<s:key name="can_write">(\d+)</s:key>', xmlStr)
        try:
            return match.group(1)
        except AttributeError as e:
            print(xmlStr)
            return 0

    def get_eai_user_name(self, xmlStr):
        if sys.version_info.major >= 3:
            xmlStr = str(xmlStr, "utf-8")
        match = re.search(r'<s:key name="eai:userName">([\w-]+)</s:key>', xmlStr)
        try:
            return match.group(1)
        except AttributeError as e:
            print(xmlStr)
            return "nobody"

    def get_things(self, owner, name, particular_session_key):
        uri = self.uri  % (owner, "")
        response, content = splunk.rest.simpleRequest(uri, sessionKey=particular_session_key, method='GET', raiseAllErrors=True)
        return response["status"], content

    def get_thing(self, owner, name, particular_session_key):
        uri = self.uri  % (owner, name)
        response, content = splunk.rest.simpleRequest(uri, sessionKey=particular_session_key, method='GET', raiseAllErrors=True)
        return response["status"], content

    def create_thing(self, owner, name, particular_session_key):
        uri = self.uri % (owner, "")
        postargs = self.get_post_args(name)
        response, content = splunk.rest.simpleRequest(uri, sessionKey=particular_session_key, postargs=postargs, method='POST', raiseAllErrors=True)
        return response["status"], content

    def change_thing(self, owner, name, particular_session_key):
        uri = self.uri % (owner, name)
        postargs = self.get_post_args()
        response, content = splunk.rest.simpleRequest(uri, sessionKey=particular_session_key, postargs=postargs, method='POST', raiseAllErrors=True)
        return response["status"], content

    def delete_thing(self, owner, name, particular_session_key):
        uri = self.uri  % (owner, name)
        response, content = splunk.rest.simpleRequest(uri, sessionKey=particular_session_key, method='DELETE', raiseAllErrors=True)
        return response["status"], content

    def set_sharing(self, owner, name, sharing, readPerms, writePerms, particular_session_key):
        uri = self.uri + "/acl"
        uri = uri % (owner, name)
        assert(sharing in ["user", "app", "global"])
        postargs = {
            "sharing":sharing,
            "owner":owner,
            "perms.read": readPerms
        }
        if writePerms:
            postargs["perms.write"] = writePerms
        response, content = splunk.rest.simpleRequest(uri, sessionKey=particular_session_key, postargs=postargs, method='POST', raiseAllErrors=True)
        return response["status"], content


    def check_all_users_can_create_AND_see_own_things_using_either_nobody_or_username(self):
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            db_name = "%s-%s" % (self.private_name, usernames[i])
            status, response = self.create_thing(user, db_name, key)
            self.assertEqual("201", status, "creating dashboard, and we got a status of %s" % status)
            status, response = self.get_thing(user, db_name, key)
            self.assertEqual("200", status, "%s tried to see their own dashboard using their own username and got %s" % (user, status))

            #but... now that it was created with a username you can't use nobody to get it.
            with self.assertRaises(splunk.ResourceNotFound):
                status, response = self.get_thing("nobody", db_name, key)

            self.delete_thing(user, db_name, key)

            status, response = self.create_thing("nobody", db_name, key)
            self.assertEqual("201", status, "creating dashboard, and we got a status of %s" % status)
            status, response = self.get_thing("nobody", db_name, key)
            self.assertEqual("200", status, "%s tried to see their own dashboard using nobody as owner and got %s" % (user, status))
            #and vice versa, you can't use your own username to get one you created with "nobody".
            status, response = self.get_thing(user, db_name, key)
            self.assertEqual("200", status, "even though %s created this dashboard with 'nobody', they can see it using their own username (status=%s)" % (user, status))

            self.delete_thing("nobody", db_name, key)

    def check_all_users_can_see_app_level_things_owned_by_admin_using_either_nobody_or_username(self):
        status, response = self.create_thing(admin1_username, self.public_name, admin_session_key)
        self.set_sharing(admin1_username, self.public_name, "app", "*", "admin", admin_session_key)
        for i in range(4):
            username = usernames[i]
            key = session_keys[i]
            status, response = self.get_thing("nobody", self.public_name, key)
            self.assertEqual("200", status, "%s tried to see a shared dashboard using nobody as owner and got %s" % (usernames[0], status))
            status, response = self.get_thing(username, self.public_name, key)
            self.assertEqual("200", status, "%s tried to see a shared dashboard using their own username and got %s" % (usernames[0], status))

    def check_all_users_can_post_changes_to_own_things_using_username(self):
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            name = "%s-%s" % (self.private_name, usernames[i])
            status, response = self.create_thing(user, name, key)
            status, response = self.change_thing(user, name, key)
            self.assertEqual("200", status, "%s tried to POST a change and got %s" % (user, status))

    def check_no_users_can_post_changes_to_own_things_using_nobody(self):
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            db_name = "%s-%s" % (self.private_name, usernames[i])
            status, response = self.create_thing(user, db_name, key)
            # and a 404 for some reason instead of a 400?  Good times.
            with self.assertRaises(splunk.ResourceNotFound):
                status, response = self.change_thing("nobody", db_name, key)

    def check_no_users_can_post_changes_to_shared_and_properly_acled_things_using_username(self):
        status, response = self.create_thing(admin1_username, self.public_name, admin_session_key)
        self.set_sharing(admin1_username, self.public_name, "app", "*", "admin,power,user", admin_session_key)
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            with self.assertRaises(splunk.ResourceNotFound):
                status, response = self.change_thing(user, self.public_name, key)


    def check_all_users_can_post_changes_to_shared_and_properly_acled_things_using_nobody(self):
        status, response = self.create_thing(admin1_username, self.public_name, admin_session_key)
        self.set_sharing(admin1_username, self.public_name, "app", "*", "admin,power,user", admin_session_key)
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            status, response = self.change_thing("nobody", self.public_name, key)
            self.assertEqual("200", status, "%s user, if they use 'nobody' in the URL, should be able to post changes to an app-level dashboard shared with all roles, but got %s" % (user, status))

    def check_own_private_things_are_marked_writable(self):
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            name = "%s-%s" % (self.private_name, usernames[i])
            status, response = self.create_thing(user, name, key)
            status, response = self.get_thing(user, name, key)
            canWrite = self.get_writable_flag(response)
            self.assertEqual("1", canWrite, "our own private dashboards should be marked as writable")

    def check_shared_but_private_things_of_others_are_marked_non_writable_for_non_admins(self):
        failing_cases = []
        passing_cases = []
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            name = "%s-%s" % (self.private_name, usernames[i])
            self.create_thing(user, name, key)
            self.set_sharing(user, name, "app", "*", False, key)

            for j in range(4):
                #ignore the users own things
                if i == j: continue
                readUser = usernames[j]
                readUserKey = session_keys[j]

                #print("testing when %s (%s) gets things owned by %s (%s)" % (readUser, j, user, i))


                status, response = self.get_thing(readUser, name, readUserKey)

                canWrite = self.get_writable_flag(response)
                if j == 1:
                    self.assertEqual("1", canWrite, "%s has godlike powers and everything is writable for her MOU HA HA HA HA (writable=%s)" % (readUser, canWrite))
                elif j == 0:
                    self.assertEqual("1", canWrite, "THIS IS WRONG. But it's what splunk does. %s is only an admin and doesnt have admin_all_objects but %s's things are marked writable=%s" % (readUser, user, canWrite))
                    #self.assertEqual("0", canWrite, "Wait what? %s is just a normal admin user and doesn't have admin_all_objects... but for some reason when she gets something owned by %s, it has writable=%s??" % (readUser, user, canWrite))
                else:
                    if canWrite == "1":
                        failing_cases.append("FAIL - %s's non-editable thing is marked writable for user=%s" % (user, readUser))
                    else:
                        passing_cases.append("PASS - %s's non-editable thing is marked non-writable for user=%s" % (user, readUser))

                # BIZARRE EXCEPTION but i dont care about it.  Only dashboards have this key
                #eaiUserName = self.get_eai_user_name(response)
                #self.assertEqual(readUser, eaiUserName, "the eai:usename is a dumb thing that echoes back the eai username you just used.. %s" % eaiUserName)

                # writable=1 hey?  Well let's see about that... LET'S WRITE TO THEM ALL !!!!!
                # but remember kids...we have to NOT solemnly say our name out loud
                # in other words we have to use "nobody"  in our URL.
                # or the bear will eat us.
                if canWrite == "1":
                    try:
                        status, response = self.change_thing("nobody", name, readUserKey)
                        passing_cases.append("PASS - %s's non-editable thing -- we actually changed it with user=%s" % (user, readUser))
                    except splunk.AuthorizationFailed as e:
                        failing_cases.append("FAIL - Splunk lied to us and said %s's non-editable thing was writable for user=%s" % (user, readUser))
                else:

                    with self.assertRaises(splunk.AuthorizationFailed):
                        status, response = self.change_thing("nobody", name, readUserKey)

        if len(failing_cases) > 0:
            print("these cases fail")
            print("\n".join(failing_cases))
            print("these cases passed")
            print("\n".join(passing_cases))
        self.assertEqual(0, len(failing_cases), "Strange things were afoot at the Circle K")


    def check_uberadmins_can_see_private_things_using_username(self):
        status, response = self.create_thing(user_username, self.private_name, user_session_key)
        self.set_sharing(user_username, self.private_name, "user", "user", "user", user_session_key)
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            if i == 1:
                status, response = self.get_thing(user_username, self.private_name, key)
                self.assertEqual("200", status, "%s user, if they use 'nobody' in the URL, should be able to post changes to an app-level dashboard shared with all roles, but got %s" % (user, status))

                status, response = self.get_thing(user_username, self.private_name, key)
                self.assertEqual("200", status, "%s user, if they use 'nobody' in the URL, should be able to post changes to an app-level dashboard shared with all roles, but got %s" % (user, status))

                status, response = self.get_things(user_username, self.private_name, key)
                self.assertEqual("200", status, "%s user, if they use 'nobody' in the URL, should be able to post changes to an app-level dashboard shared with all roles, but got %s" % (user, status))


                continue
            elif i == 3:
                continue
            else:
                with self.assertRaises(splunk.AuthorizationFailed):
                    status, response = self.get_thing(user_username, self.private_name, key)





class TestSavedSearchREST(CoreSplunkTestCase):

    uri = "/servicesNS/%s/cisco_cdr/saved/searches/%s"
    private_name = "a_private_saved_search"
    public_name = "a_public_saved_search"


    def test_counttype_arg(self):

        uri = self.uri % (admin1_username, "")
        postargs = self.get_post_args(self.private_name)
        postargs["counttype"] = "Number of events"
        # splunk has counttype in savedsearches.conf.spec but for this key and a few others, this is illegal in REST
        with self.assertRaises(splunk.BadRequest):
            response, content = splunk.rest.simpleRequest(uri, sessionKey=admin_session_key, postargs=postargs, method='POST', raiseAllErrors=True)
        #silly developer.  you have to know that 
        postargs["alert_type"] = postargs["counttype"]
        del postargs["counttype"]

        response, content = splunk.rest.simpleRequest(uri, sessionKey=admin_session_key, postargs=postargs, method='POST', raiseAllErrors=True)
        #manual clean up is unnecessary because the class already deletes this name for admin1 and admin2
        #self.delete_thing(admin1_username, self.private_name, admin_session_key)


    def get_post_args(self, name=False):
        post_args = {
            "search": 'foo | eval bar="%s" | timechart count' % time.time()
        }
        if name:
            post_args["name"] = name
        return post_args

    def test_all_users_can_post_changes_using_username(self):
        self.check_all_users_can_post_changes_to_own_things_using_username()

    def test_all_users_can_see_app_level_reports_owned_by_admin_using_either_nobody_or_username(self):
        self.check_all_users_can_see_app_level_things_owned_by_admin_using_either_nobody_or_username()


    def test_no_users_can_post_changes_to_own_report_using_nobody(self):
        self.check_no_users_can_post_changes_to_own_things_using_nobody()

    def test_bizarre_exception_that_users_can_post_changes_to_shared_and_properly_acled_reports_using_username(self):
        """ saved searches are different.  but why?  """
        status, response = self.create_thing(admin1_username, self.public_name, admin_session_key)
        self.set_sharing(admin1_username, self.public_name, "app", "*", "admin,power,user", admin_session_key)
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            status, response = self.change_thing(user, self.public_name, key)
            self.assertEqual("200", status)

    def test_all_users_can_post_changes_to_shared_and_properly_acled_report_using_nobody(self):
        self.check_all_users_can_post_changes_to_shared_and_properly_acled_things_using_nobody()

    def test_own_private_reports_are_marked_writable(self):
        self.check_own_private_things_are_marked_writable()

    def test_shared_but_private_reports_of_others_are_marked_non_writable_for_non_admins(self):
        self.check_shared_but_private_things_of_others_are_marked_non_writable_for_non_admins()

    def test_uberadmins_can_see_private_things_using_username(self):
        self.check_uberadmins_can_see_private_things_using_username()

class TestDashboardPanelREST(CoreSplunkTestCase):

    uri = "/servicesNS/%s/cisco_cdr/data/ui/views/%s"
    private_name = "a_private_test_dashboard"
    public_name = "a_public_test_dashboard"

    def get_post_args(self, name=False):
        post_args = {
            "eai:data": """<dashboard>
  <label>$dashboardName.rawValue$ - %s</label>
  <row>
  <table>
    <search>
      <query>
        | makeresults count=10 | eval fish="&lt;')))))&lt;"
      </query>
    </search>
  </table>
  </row>
  </dashboard>""" % time.time()
        }
        if name:
            post_args["name"] = name
        return post_args



    # -------------------------------------------------------------------------
    # There once were four little users and they lived with a bear.
    # they liked to make their own toys and play with them.
    # -------------------------------------------------------------------------
    def test_all_users_can_create_AND_see_own_things_using_either_nobody_or_username(self):
        self.check_all_users_can_create_AND_see_own_things_using_either_nobody_or_username()

    # -------------------------------------------------------------------------
    # and they could see their own toys quite easily.
    # -------------------------------------------------------------------------
    def test_all_users_can_see_app_level_dashboard_owned_by_admin_using_either_nobody_or_username(self):
        self.check_all_users_can_see_app_level_things_owned_by_admin_using_either_nobody_or_username()

    # -------------------------------------------------------------------------
    # Now the bear would let each of them touch the toys they had made, IF they
    # solemnly spoke their own names aloud when doing so.
    # -------------------------------------------------------------------------
    def test_all_users_can_post_changes_using_username(self):
        self.check_all_users_can_post_changes_to_own_things_using_username()

    # -------------------------------------------------------------------------
    # But one day they forgot to solemnly say their own names when they
    # touched their toys and the bear ate their feet to teach them a lesson.
    # -------------------------------------------------------------------------
    def test_no_users_can_post_changes_to_own_dashboard_using_nobody(self):
        self.check_no_users_can_post_changes_to_own_things_using_nobody()

    # -------------------------------------------------------------------------
    # Until one day they each touched something belonging to someone else while
    # saying their own name like they had been taught, and this was wrong so
    # the bear ate their hands to teach them a lesson.
    # -------------------------------------------------------------------------
    def test_no_users_can_post_changes_to_shared_and_properly_acled_dashboard_using_username(self):
        status, response = self.create_thing(admin1_username, self.public_name, admin_session_key)
        self.set_sharing(admin1_username, self.public_name, "app", "*", "admin,power,user", admin_session_key)
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            with self.assertRaises(splunk.ResourceNotFound):
                status, response = self.change_thing(user, self.public_name, key)

    # -------------------------------------------------------------------------
    # so OK they tried to remember that one, and they DIDN'T solemnly say their
    # own names when touching other people's things.
    # -------------------------------------------------------------------------
    def test_all_users_can_post_changes_to_shared_and_properly_acled_dashboard_using_nobody(self):
        self.check_all_users_can_post_changes_to_shared_and_properly_acled_things_using_nobody()


    # -------------------------------------------------------------------------
    # And there was one user that the bear thought was special who carried around
    # a little badge saying "admin-all-objects".
    # The bear let that user go around and look at everyone's toys even the secret
    # embarassing ones that they had tried to hide.
    # Well, as long as it solemnly spoke the OWNERS name and not its own name AND
    # definitely not no name at all,  while messing with another user's things.
    # -------------------------------------------------------------------------
    def test_uberadmins_can_see_private_things_using_username(self):
        self.check_uberadmins_can_see_private_things_using_username()


    # -------------------------------------------------------------------------
    # And the admin-all-objects user was the only one who the bear would let get
    # away with this behavior.
    # When the other user who thought they were an admin tried to do it, the bear
    # ate part of their arm.
    # -------------------------------------------------------------------------
    def test_admin_cannot_see_or_post_changes_to_uberadmins_dashboard(self):
        status, response = self.create_thing(admin2_username, self.private_name, uber_admin_session_key)
        with self.assertRaises(splunk.ResourceNotFound):
            status, response = self.get_thing(admin1_username, self.private_name, admin_session_key)
        with self.assertRaises(splunk.ResourceNotFound):
            status, response = self.change_thing(admin1_username, self.private_name, admin_session_key)
        with self.assertRaises(splunk.ResourceNotFound):
            status, response = self.change_thing("nobody", self.private_name, admin_session_key)



    # -------------------------------------------------------------------------
    # then the bear pointed out that the users were being silly because  all this
    # time, printed in tiny letters on everything was a tiny pair of marks, "owner"
    # and "isWritable", that told them exactly whether they could play with the toy,
    # AND whether they had to solemnly speak their own name when doing so.
    # -------------------------------------------------------------------------
    def test_own_private_dashboards_are_marked_writable(self):
        self.check_own_private_things_are_marked_writable()

        # BIZARRE EXCEPTION - magic keys that only dashboards have.
        for i in range(4):
            user = usernames[i]
            key = session_keys[i]
            name = "%s-%s" % (self.private_name, usernames[i])
            status, response = self.get_thing(user, name, key)
            receivedEaiUserName = self.get_eai_user_name(response)
            message = "our own private dashboards should have our name (%s) as eai:username but instead received %s" % (user, receivedEaiUserName)
            self.assertEqual(user, receivedEaiUserName, message)


    # -------------------------------------------------------------------------
    # But then the users looked more closely at the tiny marks and noticed that
    # the bear had lost its mind long ago.  It seemed that the bear believed that
    # all "admin" users automatically had the admin-all-objects capability, because
    # the tiny marks were inscribed according to this idea.
    # the non admin-all-objects admin pointed emphatically to the chunk that had been
    # eaten out of his arm.
    # The uberadmin user found the inconsistency deeply disturbing and when he
    # confronted the bear about it the bear ate them all. The End.
    # -------------------------------------------------------------------------
    def test_shared_but_private_dashboards_of_others_are_marked_non_writable_for_non_admins(self):
        self.check_shared_but_private_things_of_others_are_marked_non_writable_for_non_admins()






if __name__ == '__main__':
    unittest.main()
