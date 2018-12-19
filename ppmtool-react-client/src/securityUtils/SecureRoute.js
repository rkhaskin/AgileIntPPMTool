import React from "react";
import { Route, Redirect } from "react-router-dom";
import { connect } from "react-redux";
import PropTypes from "prop-types";

const SecuredRoute = (props) => (
  <Route  
    {...props}
    render={props => props.security.validToken === true ? (<props.component {...props} />) : (<Redirect to="/login" />)
    }
  />
);
/*
const SecuredRoute = ({ component: Component, security, ...otherProps }) => (
  <Route  
    {...otherProps}
    render={props => security.validToken === true ? (<Component {...props} />) : (<Redirect to="/login" />)
    }
  />
);
*/

SecuredRoute.propTypes = {
  security: PropTypes.object.isRequired
};

const mapStateToProps = state => ({
  security: state.security
});

export default connect(mapStateToProps)(SecuredRoute);
