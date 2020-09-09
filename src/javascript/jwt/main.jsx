import React from 'react';
import ReactDOM from 'react-dom';
import App from "./App";
import {CssBaseline} from "@material-ui/core";

window.reactRenderJWTApp = function(target, id, dxContext) {
    ReactDOM.render(
        <React.Fragment>
            <CssBaseline />
            <App id={id} dxContext={dxContext}/>
        </React.Fragment>, document.getElementById(target));
};
