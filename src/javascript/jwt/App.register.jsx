import React, {Suspense} from 'react';
import {registry} from '@jahia/ui-extender';
import {Jwt} from '@jahia/moonstone';
import {ProgressPaper} from '@jahia/design-system-kit';

window.jahia.i18n.loadNamespaces('security-filter-tools');
const Component = React.lazy(() => import('./App'));

registry.add('adminRoute', 'jwtConfiguration', {
    targets: ['developerTools:40'],
    requiredPermission: 'developerToolsAccess',
    icon: <Jwt/>,
    label: 'security-filter-tools:jwtConfiguration',
    isSelectable: true,
    render: () => <Suspense fallback={<ProgressPaper/>}><Component/></Suspense>
});
