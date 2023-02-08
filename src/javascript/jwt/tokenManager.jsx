import React from 'react';
import {withStyles} from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import {Add, Button, Edit} from '@jahia/moonstone';
import TokenEditor from './tokenEditor';
import PropTypes from 'prop-types';

const styles = {
    root: {
        flexGrow: 1,
        padding: 30
    },
    textArea: {
        width: 500,
        height: 100
    },
    loginContainer: {
        display: 'flex',
        alignItems: 'center',
        margin: '20px;'
    }
};

class TokenManager extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            showEditCreateDialog: false,
            token: null
        };
        this.toggleDialog = this.toggleDialog.bind(this);
        this.onTokenCreation = this.onTokenCreation.bind(this);
    }

    onTokenCreation(token) {
        this.setState({
            token: token
        });
    }

    render() {
        let {classes} = this.props;
        let {token, showEditCreateDialog} = this.state;
        if (token === null) {
            return this.addToken();
        }

        return (
            <div className={classes.root}>
                <TokenEditor open={showEditCreateDialog}
                             close={this.toggleDialog}
                             onTokenCreation={this.onTokenCreation}
                             {...this.getClaims(token.claims)}/>
                <p>
                    <textarea readOnly className={classes.textArea} value={token.token}/>
                    {this.editButton()}
                </p>
            </div>
        );
    }

    addToken() {
        return (
            <div>
                <TokenEditor open={this.state.showEditCreateDialog}
                             close={this.toggleDialog}
                             scopes=""
                             referer=""
                             ips=""
                             onTokenCreation={this.onTokenCreation}/>
                <Tooltip title="Add token" placement="top-start">
                    <Button variant="ghost"
                            size="big"
                            icon={<Add/>}
                            onClick={() => this.setState({showEditCreateDialog: true})}/>
                </Tooltip>
            </div>
        );
    }

    editButton() {
        return <Button variant="ghost" size="big" icon={<Edit/>} onClick={() => this.toggleDialog()}/>;
    }

    toggleDialog() {
        this.setState(previousSate => {
            return {
                ...previousSate,
                showEditCreateDialog: !previousSate.showEditCreateDialog
            };
        });
    }

    getClaims(claimsJson) {
        if (claimsJson) {
            const claims = JSON.parse(claimsJson);
            return {
                scopes: claims.scopes.join(','),
                referer: claims.referer ? claims.referer.join(',') : '',
                ips: claims.ips ? claims.ips.join(',') : ''
            };
        }

        return {
            scopes: '',
            referer: '',
            ips: ''
        };
    }
}

TokenManager.propTypes = {
    dxContext: PropTypes.object.isRequired,
    classes: PropTypes.object.isRequired
};

export default withStyles(styles)(TokenManager);
