"""This program generates a simple website for the user to view which
gives details about a DnD adventure called 'The Black Library', which
contains back ground information, maps and encounters for players, as well as
linking to external useful websites. To access the maps the user must first register
with the website and be logged in."""

# import needed modules
import datetime
import string
import os
import logging
from flask import Flask, render_template, flash, redirect, request, session, url_for
from passlib.hash import sha256_crypt

# create directory to password and username data for users, gobal for ease of
# access, create directory to log data for admin use global as well
Pass_Directory = os.path.dirname(os.path.realpath(__file__)) + '\\passdata.txt'
Blacklisted_Directory = os.path.dirname(
    os.path.realpath(__file__)) + '\\CommonPassword.txt'
Log_Directory = os.path.dirname(os.path.realpath(__file__)) + '\\log.txt'

# set up logger to hand warning level logs, set handler to print to log directory log.txt
Logger = logging.getLogger(name='w')
Logger.setLevel(level=logging.WARNING)
Logger.addHandler(hdlr=logging.FileHandler(filename=Log_Directory, encoding='utf-8'))


# start of fucntions the flask app will use
def log_invalid_login(username, request_ip):
    """This fucntion will log an invalid login attempt for usernames
    when a user inputs an invalid password, and print the warning to log.txt"""

    # get current date time
    date_time = datetime.datetime.today()
    # remove microseconds from time and set space as the separator
    # set this as date time
    date_time = date_time.isoformat(sep=' ', timespec='seconds')

    # format passed info in a string
    log_info = (f'WARNING!-->INVALID LOGIN/PASSWORD CHANGE ATTEMPT -- Time: {date_time} '
                f'-- Username: {username} -- Requesting IP: {request_ip}')

    # print log info to log.txt
    Logger.warning(log_info)


def username_is_in_use(username):
    """This function will check if the user has input a
    username that has already been used, as listed in
    passdata.txt."""

    # set returned boolean as false prior to file opening
    valid_credentials = False

    # open and read file at Pass Directory, set as pass data
    with open(Pass_Directory, 'r', encoding='utf-8') as pass_data:

        # convert data to a list
        data = pass_data.readlines()

        # for each line in the list data
        for line in data:

            # set up variable to slice the \n off the end of
            # the line in the data list
            cut = slice(0, -1)

            # if the passed username matches any encrypted username in the
            # pass data file
            if sha256_crypt.verify(username, line[cut]):

                # set valid credentials as true
                valid_credentials = True

    # return valid credentials
    return valid_credentials


def is_valid_pass(password):
    """This function will check if the user has input a
    password with at least one upper, lower, number, and
    special character."""

    # setup return boolean valid pass to false, then set up
    # the other required booleans that represent a valid password's
    # contents
    valid_pass = False
    has_uppers = False
    has_lowers = False
    has_numbers = False
    has_specials = False

    # define password character catagories.
    uppers = string.ascii_uppercase
    lowers = string.ascii_lowercase
    numbers = string.digits
    specials = string.punctuation

    # for each character in password, if upper, lower, numbers
    # or specials are found set that boolean to true
    for char in password:

        if char in uppers:

            has_uppers = True

        if char in lowers:

            has_lowers = True

        if char in numbers:

            has_numbers = True

        if char in specials:

            has_specials = True

        # if all password requirement booleans are true and password is atleast 12
        # in lenght than
        if (has_uppers is True and has_lowers is True and has_numbers is True and
                has_specials is True and len(password) >= 12):

            # it is a valid password
            valid_pass = True

    # return valid pass
    return valid_pass


def register_user(username, password):
    """This function will take user inputs and hash them,
    then save it to passdata.txt."""

    # hash passed user name and password
    hashed_user = sha256_crypt.hash(username)
    hashed_pass = sha256_crypt.hash(password)

    # open username and password file
    with open(Pass_Directory, 'a', encoding='utf-8') as pass_data:

        # write hashed data to file, append new line to end
        pass_data.writelines(hashed_user + '\n')
        pass_data.writelines(hashed_pass + '\n')


def is_valid_credentials(username, password, request_ip):
    """This function will scan the passdata.txt file and ensure that both
    the username is registered and that the password for that user name is
    vaild, then returns a boolean value"""

    # set up return boolean as false
    valid_credentials = False

    # open username and password file, set as pass data
    with open(Pass_Directory, 'r', encoding='utf-8') as pass_data:

        # set data as a list of the files contents
        data = pass_data.readlines()

        # set request index for the password
        next_line_index = 0

        # for each line in the data list
        for line in data:

            # count the next line index up one, (password location)
            next_line_index = next_line_index + 1

            # setup slice for \n at end of line
            cut = slice(0, -1)

            # if the input username matches a user name in the list
            if sha256_crypt.verify(username, line[cut]):

                # set the index that the corresponding password is on to
                # data[value of the next_line_index], set pass_line as that value
                pass_line = data[next_line_index]

                # if the passed password matches the next list item defined above
                if sha256_crypt.verify(password, pass_line[cut]):

                    # the user input valid credentials
                    valid_credentials = True

                # else the user did not input a valid password for that username
                else:

                    # log the invalid attempt with log invalid login function
                    log_invalid_login(username, request_ip)

    # return valid credential boolean
    return valid_credentials


def is_bad_pass(password):
    """This function will check the password the user entered
    against black listed passwords listed in CommonPassword.txt
    and return a boolean value based on the functions findings"""

    # set up return boolean
    is_blacklisted_pass = False

    # open username and password file, set as pass data
    with open(Blacklisted_Directory, 'r', encoding='utf-8') as blacklist_data:

        # set data as a list of the files contents
        data = blacklist_data.readlines()

        # for each line in the data list
        for line in data:

            # setup slice for \n at end of line
            cut = slice(0, -1)

            # if the input username matches a user name in the list
            if password == line[cut]:

                # password is blacklisted set to true
                is_blacklisted_pass = True

    # return boolean
    return is_blacklisted_pass


def update_pass(username, password):
    """This function takes the input password and updates the logged in users
    password to that value."""

    # hash new password and set up slice
    hashed_pass = sha256_crypt.hash(password)
    cut = slice(0, -1)

    # open username and password file, set as pass data
    with open(Pass_Directory, 'r', encoding='utf-8') as pass_data:

        # set data to lines read from file
        data = pass_data.readlines()

        # set password index to 0
        pass_index = 0

        # for each line in data
        for line in data:

            # incease password index by 1
            pass_index = pass_index + 1

            # if username matches the line
            if sha256_crypt.verify(username, line[cut]):

                # set hashed password as the next line "pass_index" which is current
                # index plus 1
                data[pass_index] = hashed_pass + '\n'

    # open username and password file set as pass data
    with open(Pass_Directory, 'w', encoding='utf-8') as pass_data:

        # write the amended data
        pass_data.writelines(data)


# set app as the name of file
app = Flask(__name__)
# set app secret key, this should be updated to an actual secure key
# if put into production
app.secret_key = 'A very weak key'


# if index is the route run the index function
@app.route('/')
def index():
    """This function returns the main page of the website"""

    # get current date time
    date_time = datetime.datetime.today()

    # remove microseconds from time and set space as the separator
    # set this as date time
    date_time = date_time.isoformat(sep=' ', timespec='seconds')

    # render the template index and pass date time as date time
    return render_template('index.html', date_time=date_time)


# if background is the round run the background function
@app.route('/background/')
def background():
    """This function returns the background page of the website"""

    # render the template background
    return render_template('background.html')


# if encounters is the route then run the encounters function
@app.route('/encounters/')
def encounters():
    """This function returns the encoutners page of the website"""

    # render the template encounters
    return render_template('encounters.html')


# if login is the route then run the login function
@app.route('/login/', methods=['GET', 'POST'])
def login():
    """This function returns the login page of the website"""

    # set error as none
    error = None

    # if the page method was post then
    if request.method == "POST":

        # get the information the user input into the
        # login form, get the ip address from the source of the request
        username = request.form["username"]
        password = request.form["password"]
        request_ip = request.remote_addr

        # if username was empty
        if not username:

            # set error to message
            error = "A username is required"

        # if password was empty
        elif not password:

            # set error to message
            error = "A password is required"

        # if the user did not input valid username and password, send ip for logging
        elif not is_valid_credentials(username, password, request_ip):

            # set error as message
            error = "You input an invalid username or password"

        # setup flash with error message from above
        flash(error)

        # if there was no error
        if error is None:

            # set session logged in status to true
            session['logged_in'] = True
            session['username'] = username

            # redircet user to login complete page
            return redirect(url_for("login_complete"))

    # render the login page with error, if applicable
    return render_template('login.html', error=error)


# if route is login complete then run login complete function
@app.route('/login_complete/')
def login_complete():
    """This function will display the login complete page of the website"""

    # if the user has not logged in
    if not session.get('logged_in'):

        # redirect to login page
        return redirect(url_for('login'))

    # render login complete page
    return render_template('login_complete.html')


# if route was logout run the logout function
@app.route('/logout/')
def logout():
    """This function will display the logout page and set the logged in
    status to false for the session"""

    # set logged in status for the session to false
    session['logged_in'] = False
    session['username'] = None

    # render logout page
    return render_template('logout.html')


# if register is the route then run the register function
@app.route('/register/', methods=['GET', 'POST'])
def register():
    """This function returns the register page of the website"""

    # set error to none
    error = None

    # if the page request method was post
    if request.method == "POST":

        # get username and password from register form
        username = request.form["username"]
        password = request.form["password"]

        # if username is empty
        if not username:

            # error is set to message
            error = "A username is required"

        # if password is empty
        elif not password:

            # error is set to message
            error = "A password is required"

        # call username is in use function on username (returns boolean)
        elif username_is_in_use(username):

            # if it was in use, set error to message
            error = "There is already a user with that username"

        # check if the entered password is blacklisted
        elif is_bad_pass(password):

            # error is set to message
            error = "That password is blacklisted, choose a different password."

        # call is valid pass on password (returns boolean)
        elif not is_valid_pass(password):

            # if the password was not valid, set error to message
            error = ("Your password must contain 1 upper, lower, number and special characters " +
                     "and be longer than 12 characters.")

        # setup flash with error
        flash(error)

        # if there was no error
        if error is None:

            # register the user via the register user function, pass username and password
            register_user(username, password)

            # redirect the user to registration complete page
            return redirect(url_for("reg_complete"))

    # render the register page
    return render_template("register.html", error=error)


# if the route is to the pass update run pass update function
@app.route('/pass_update/', methods=['GET', 'POST'])
def pass_update():
    """This function will show the password update page to the user"""

    # set error to none
    error = None

    # if the page request method was post
    if request.method == "POST":

        # get password data from register form, get ip address from the source of the request
        old_password = request.form["old_password"]
        password = request.form["password"]
        reentered_password = request.form["reentered_password"]
        request_ip = request.remote_addr

        # if password field is empty
        if not password:

            # error is set to message
            error = "You must enter the new password twice"

        # if reentered password field is empty
        if not reentered_password:

            # error is set to message
            error = "You must enter the new password twice"

        # if the passwords do not match
        elif password != reentered_password:

            # error is set to message
            error = "The entered passwords must match"

        # check if the entered password is blacklisted
        elif is_bad_pass(password):

            # error is set to message
            error = "That password is blacklisted, choose a different password."

        # call is valid pass on password (returns boolean)
        elif not is_valid_pass(password):

            # if the password was not valid, set error to message
            error = ("Your password must contain 1 upper, lower, number and special characters " +
                     "and be longer than 12 characters.")

        # check that user input their old password correctly
        elif not is_valid_credentials(session.get('username'), old_password, request_ip):

            # set error as message
            error = "You did not input your old password correctly"

        # setup flash with error
        flash(error)

        # if there was no error
        if error is None:

            # register the user via the register user function, pass username and password
            update_pass(session.get('username'), password)

            # redirect the user to registration complete page
            return redirect(url_for("pass_update_complete"))

    # if the user has not logged in this session
    if not session.get('logged_in'):

        # redirect user to login page
        return redirect(url_for('login'))

    return render_template('pass_update.html', error=error)


# if the route is to the pass update complete page run the pass update function
@app.route('/pass_update_complete/')
def pass_update_complete():
    """This function will display the pass update complete page to the user"""

    # if the user has not logged in this session
    if not session.get('logged_in'):

        # redirect user to login page
        return redirect(url_for('login'))

    # return the rendered pass update complete template
    return render_template('pass_update_complete.html')


# if route is reg complete then run the reg complete function
@app.route('/reg_complete/')
def reg_complete():
    """This function returns the registration complete page to the user"""

    # render the reg complete page to the user
    return render_template('reg_complete.html')


# if map table is the route then run the map table function
@app.route('/map_table/')
def map_table():
    """This function returns the map table page of the website"""

    # if the user has not logged in this session
    if not session.get('logged_in'):

        # redirect user to login page
        return redirect(url_for('login'))

    # render the map table page
    return render_template('map_table.html')


# if astra map is the route then run the astra map function
@app.route('/astra_map/')
def astra_map():
    """This function returns the Astra world map page of the website"""

    # if user has not logged in this session
    if not session.get('logged_in'):

        # redirect to login page
        return redirect(url_for('login'))

    # render the astra map page
    return render_template('astra_map.html')


# if the route is chorn loith study run the chorn loith study function
@app.route('/chorn_loith_study/')
def chorn_loith_study():
    """This function returns the first battle map page of the website"""

    # if the user has not logged in this session
    if not session.get('logged_in'):

        # redirect to login page
        return redirect(url_for('login'))

    # render the chorn loith study page
    return render_template('chorn_loith_study.html')


# if the route is chorn loith augery run the chorn loith augery function
@app.route('/chorn_loith_augery/')
def chorn_loith_augery():
    """This function returns the second battle map page of the website"""

    # if user has not logged in this session
    if not session.get('logged_in'):

        # redirect user to login page
        return redirect(url_for('login'))

    # render the chorn loith augery page
    return render_template('chorn_loith_augery.html')


# if the route is chorn loith vault run the chorn loith vault function
@app.route('/chorn_loith_vault/')
def chorn_loith_vault():
    """This function returns the third battle map page of the website"""

    # if the user has not logged in this session
    if not session.get('logged_in'):

        # redirect user to login page
        return redirect(url_for('login'))

    # render the chorn loith vault page
    return render_template('chorn_loith_vault.html')
