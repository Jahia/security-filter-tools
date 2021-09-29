import {registry} from '@jahia/ui-extender';
import register from './jwt/App.register';

export default function () {
    registry.add('callback', 'securityfiltertools', {
        targets: ['jahiaApp-init:50'],
        callback: register
    });
}
