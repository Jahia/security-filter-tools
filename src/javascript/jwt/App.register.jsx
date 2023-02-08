import React, {Suspense} from 'react';
import {registry} from '@jahia/ui-extender';
import {Jwt, Loader} from '@jahia/moonstone';

export default function () {
    window.jahia.i18n.loadNamespaces('security-filter-tools');
    const Component = React.lazy(() => import('./App'));

    registry.add('adminRoute', 'jwtConfiguration', {
        targets: ['developerTools:40'],
        requiredPermission: 'developerToolsAccess',
        icon: <Jwt/>,
        label: 'security-filter-tools:jwtConfiguration',
        isSelectable: true,
        render: () => <Suspense fallback={<Loader/>}><Component/></Suspense>
    });
}
