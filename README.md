# tucasita-api
Code inspired by https://github.com/melihcolpan/flask-restful-login

### INSTALLATION
* Python 3 is required. There are ways to send requests to server. 
* Postman, Insomnia, cURL, httpie and curl are simple and useful tools to send requests. 
* Below examples to send requests use curl

Pull project and install requirements to virtual environment (*[https://pypi.org/project/virtualenv/]()*). Then run.
```
$ git clone https://github.com/sec-dev-iteso/tucasita-api
$ cd tucasita-api
$ python3 -m venv ./venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ python -m main
```

* For requests using curl: *[https://curl.haxx.se/download.html]()*

> __Example user (buyer), property agent, admin and super admin users are created in database initializer class. You can use these users to login, logout and data handlers. For register handler, use new user information, otherwise returns already exist user.__


| Test Users        | Email Address           | Password  |
| ------------- |:-------------:| -----:|
| User          | test_email@example.com  | test_password  |
| Property Agent| agent_email@example.com | agent_password |
| Admin         | admin_email@example.com | admin_password |
| Super Admin   | sa_email@example.com    |    sa_password |

#### Register:

* Curl Request:
```sh
curl -H "Content-Type: application/json" --data '{"username":"example","password":"example_password", "email":"example@example.com", "role":"property_agent", "phone":"523333333333", "address":"Some address 123, Someplace", "agency_name":"TuCasita Agency", "area":"Tlaquepaque"}' http://localhost:5000/v1/auth/register
```

#### Login:
* Curl Request:
```sh
curl -H "Content-Type: application/json" --data '{"email":"example@example.com", "password":"example_password"}' http://localhost:5000/v1/auth/login
```
> Response: Got access token and refresh token!
> Try with the default users to see different responses. 

#### Refresh Token:
* Curl Request:
```sh
curl -H "Content-Type: application/json" -H "Authorization: Bearer ACCESS_TOKEN" --data '{"refresh_token":"REFRESH_TOKEN"}' http://localhost:5000/v1/auth/refresh
```

#### Logout:
* Curl Request:
```sh
curl -H "Content-Type: application/json" -H "Authorization: Bearer ACCESS_TOKEN" --data '{"refresh_token":"REFRESH_TOKEN"}' http://localhost:5000/v1/auth/logout
```

#### Reset Password:
* Curl Request:
```sh
curl -H "Content-Type: application/json" -H "Authorization: Bearer ACCESS_TOKEN" --data '{"old_pass":"OLD-PASSWORD", "new_pass":"NEW-PASSWORD"}' http://localhost:5000/v1/auth/password_reset
```
