import React, { Component } from 'react';
import { Route, Switch } from 'react-router-dom';

import signup from './Pages/SignUp';

class App extends Component {
  render() {
    return (
      <div>
        <Switch>
          <Route path='/signup' component={signup} />

        </Switch>
      </div>
    );
  }
}

export default App;