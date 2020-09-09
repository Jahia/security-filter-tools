import React from 'react';
import PropTypes from 'prop-types';
import {withStyles} from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import TokenManager from './tokenManager';

const styles = {
    root: {
        flexGrow: 1,
    },
};

function App(props) {
    const {classes, dxContext} = props;
    return (
        <div className={classes.root}>
            <AppBar position="static" color="default">
                <Toolbar>
                    <Typography variant="title" color="inherit">
                        Configure Json Web Token
                    </Typography>
                </Toolbar>
            </AppBar>
            <TokenManager dxContext={dxContext}/>
        </div>
    );
}

App.propTypes = {
    classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(App);
