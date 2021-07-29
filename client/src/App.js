import React, { Component } from 'react';
import { Route, Switch } from 'react-router-dom';
import './index.css';
import signupScreen from './Screens/SignUp';
import loginScreen from './Screens/LogIn';
import profileScreen from './Screens/Profile';
import forgotPassScreen from './Screens/ForgotPass';
import resetPassScreen from './Screens/ResetPass';

class App extends Component {
  render() {
    return (
      <div>
        <Switch>
          <Route exact path='/signup' component={signupScreen} />
          <Route exact path='/login' component={loginScreen} />
          <Route exact path='/profile' component={profileScreen} />
          <Route exact path='/forgotpassword' component={forgotPassScreen} />
          <Route exact path='/api/v1/users/resetPassword/:resetToken' component={resetPassScreen} />
        </Switch>
      </div>
    );
  }
}

export default App;