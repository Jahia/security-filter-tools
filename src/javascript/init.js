import {registry} from '@jahia/ui-extender';
import register from './jwt/App.register';
// Ensure @apollo/react-hooks is bundled as a shared Module Federation dependency
// eslint-disable next-line no-undef

export default function () {
    registry.add('callback', 'securityfiltertools', {
        targets: ['jahiaApp-init:50'],
        callback: register
    });
}
