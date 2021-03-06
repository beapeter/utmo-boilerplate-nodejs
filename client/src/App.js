import React, { Component } from 'react';

class App extends Component {
  state = {
    greet: [],
  }

  componentDidMount() {
    fetch('/api/v1/users')
      .then(res => res.json())
      .then(greet => this.setState({ greet }));
  }

  render() {
    return (
      <div className="App">
        <h1>utmo</h1>
        {this.state.greet.map(greet => <div key={greet.id}>{greet.type}</div>)}
      </div>
    );
  }
}

export default App;
