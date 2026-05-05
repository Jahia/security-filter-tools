import {registry} from '@jahia/ui-extender';
import register from './jwt/App.register';
// Ensure @apollo/react-hooks is bundled as a shared Module Federation dependency
// eslint-disable-next-line no-unused-vars
import {useQuery} from '@apollo/react-hooks'; // NOSONAR

export default function () {
    registry.add('callback', 'securityfiltertools', {
        targets: ['jahiaApp-init:50'],
        callback: register
    });
}
