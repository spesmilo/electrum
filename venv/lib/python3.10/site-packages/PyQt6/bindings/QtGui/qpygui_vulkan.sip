// This is the SIP specifications of the Vulkan support.
//
// Copyright (c) 2026 Riverbank Computing Limited <info@riverbankcomputing.com>
// 
// This file is part of PyQt6.
// 
// This file may be used under the terms of the GNU General Public License
// version 3.0 as published by the Free Software Foundation and appearing in
// the file LICENSE included in the packaging of this file.  Please review the
// following information to ensure the GNU General Public License version 3.0
// requirements will be met: http://www.gnu.org/copyleft/gpl.html.
// 
// If you do not wish to use this file under the terms of the GPL version 3.0
// then you may purchase a commercial license.  For more information contact
// info@riverbankcomputing.com.
// 
// This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
// WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.


%If (PyQt_Vulkan)

%ModuleCode
#include <qvulkaninstance.h>
%End
typedef void *VkSurfaceKHR;


struct QVulkanExtension
{
%TypeHeaderCode
#include <qvulkaninstance.h>
%End

    QByteArray name;
    unsigned version;   // Actually uint32_t.

    Py_hash_t __hash__() const;
%MethodCode
        sipRes = qHash(*sipCpp);
%End
};

bool operator==(const QVulkanExtension &, const QVulkanExtension &);
bool operator!=(const QVulkanExtension &, const QVulkanExtension &);


struct QVulkanLayer
{
%TypeHeaderCode
#include <qvulkaninstance.h>
%End

    QByteArray description;
    QByteArray name;
    QVersionNumber specVersion;
    unsigned version;   // Actually uint32_t.

    Py_hash_t __hash__() const;
%MethodCode
        sipRes = qHash(*sipCpp);
%End
};

bool operator==(const QVulkanLayer &, const QVulkanLayer &);
bool operator!=(const QVulkanLayer &, const QVulkanLayer &);


class QVulkanInstance
{
%TypeHeaderCode
#include <qvulkaninstance.h>
%End

public:
    QVulkanInstance();
    ~QVulkanInstance();

    QVersionNumber apiVersion() const;
    void setApiVersion(const QVersionNumber &vulkanVersion);
    QVersionNumber supportedApiVersion() const;

    QList<QVulkanExtension> supportedExtensions() const;
    QList<QVulkanLayer> supportedLayers() const;

    bool create();
    void destroy();
    bool isValid() const;

    static VkSurfaceKHR surfaceForWindow(QWindow *window);

private:
    QVulkanInstance(const QVulkanInstance &);
};

%End
