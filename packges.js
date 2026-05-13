/**
 * CyberWolf FireWall - Firewall Management
 * Handles firewall rules and security features
 */

document.addEventListener('DOMContentLoaded', function() {
    // Load firewall rules when the firewall page is shown
    const firewallNavLink = document.querySelector('nav a[data-page="firewall"]');
    if (firewallNavLink) {
      firewallNavLink.addEventListener('click', function() {
        loadFirewallRules();
      });
    }
    
    // Setup rule action handlers
    setupRuleActionHandlers();
  });
  
  /**
   * Loads firewall rules from the API
   */
  function loadFirewallRules() {
    fetch('/api/firewall/rules')
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(data => {
        updateRulesTable(data.rules);
      })
      .catch(error => {
        console.error('Error fetching firewall rules:', error);
        showErrorMessage('Failed to load firewall rules');
      });
  }
  
  /**
   * Updates the rules table with the provided rules
   */
  function updateRulesTable(rules) {
    const tableBody = document.querySelector('#rules-table tbody');
    if (!tableBody) return;
    
    // Clear existing rows
    tableBody.innerHTML = '';
    
    if (rules.length === 0) {
      // Show no rules message
      const row = document.createElement('tr');
      row.innerHTML = '<td colspan="5" class="text-center">No rules defined</td>';
      tableBody.appendChild(row);
      return;
    }
    
    // Add each rule to the table
    rules.forEach((rule, index) => {
      const row = document.createElement('tr');
      row.setAttribute('data-rule-id', index);
      
      const statusClass = rule.enabled ? 'active' : 'inactive';
      const statusText = rule.enabled ? 'Active' : 'Inactive';
      const toggleText = rule.enabled ? 'Disable' : 'Enable';
      
      row.innerHTML = `
        <td>${rule.type}</td>
        <td>${rule.target}</td>
        <td>${rule.description}</td>
        <td><span class="status ${statusClass}"></span> ${statusText}</td>
        <td>
          <button class="small-btn toggle-rule" data-rule-id="${index}">${toggleText}</button>
          <button class="small-btn delete-rule" data-rule-id="${index}">Delete</button>
        </td>
      `;
      
      tableBody.appendChild(row);
    });
    
    // Re-attach event handlers
    attachRuleButtonHandlers();
  }
  
  /**
   * Sets up handlers for rule actions
   */
  function setupRuleActionHandlers() {
    // Add rule form submission is handled in scripts.js
    
    // Attach handlers to existing rule buttons
    attachRuleButtonHandlers();
  }
  
  /**
   * Attaches event handlers to rule action buttons
   */
  function attachRuleButtonHandlers() {
    // Toggle rule buttons
    const toggleButtons = document.querySelectorAll('.toggle-rule');
    toggleButtons.forEach(button => {
      button.addEventListener('click', function() {
        const ruleId = this.getAttribute('data-rule-id');
        toggleRule(ruleId);
      });
    });
    
    // Delete rule buttons
    const deleteButtons = document.querySelectorAll('.delete-rule');
    deleteButtons.forEach(button => {
      button.addEventListener('click', function() {
        const ruleId = this.getAttribute('data-rule-id');
        deleteRule(ruleId);
      });
    });
  }
  
  /**
   * Toggles a firewall rule's enabled state
   */
  function toggleRule(ruleId) {
    fetch('/api/firewall/rule/toggle', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rule_id: ruleId }),
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Refresh rules to show updated state
        loadFirewallRules();
      } else {
        showErrorMessage('Failed to toggle rule: ' + data.message);
      }
    })
    .catch(error => {
      console.error('Error toggling rule:', error);
      showErrorMessage('Failed to toggle rule');
    });
  }
  
  /**
   * Deletes a firewall rule
   */
  function deleteRule(ruleId) {
    if (confirm('Are you sure you want to delete this rule?')) {
      fetch('/api/firewall/rule/remove', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rule_id: ruleId }),
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          // Refresh rules to show updated list
          loadFirewallRules();
        } else {
          showErrorMessage('Failed to delete rule: ' + data.message);
        }
      })
      .catch(error => {
        console.error('Error deleting rule:', error);
        showErrorMessage('Failed to delete rule');
      });
    }
  }
  
  /**
   * Shows an error message to the user
   */
  function showErrorMessage(message) {
    alert(message);
  }
  
  /**
   * Validates an IP address format
   */
  function isValidIP(ip) {
    const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    if (!ipPattern.test(ip)) return false;
    
    const parts = ip.split('.');
    for (let i = 0; i < parts.length; i++) {
      const part = parseInt(parts[i]);
      if (part < 0 || part > 255) return false;
    }
    
    return true;
  }
  
  /**
   * Validates a MAC address format
   */
  function isValidMAC(mac) {
    const macPattern = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    return macPattern.test(mac);
  }
  
  /**
   * Validates a port number
   */
  function isValidPort(port) {
    const portNum = parseInt(port);
    return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
  }
  
  /**
   * Validates rule input based on rule type
   */
  function validateRuleInput(type, target) {
    switch (type) {
      case 'block-ip':
      case 'allow-ip':
      case 'throttle-ip':
        return isValidIP(target) ? true : 'Invalid IP address format';
        
      case 'block-mac':
      case 'allow-mac':
        return isValidMAC(target) ? true : 'Invalid MAC address format';
        
      case 'block-port':
        return isValidPort(target) ? true : 'Invalid port number';
        
      default:
        return 'Unknown rule type';
    }
  }
  