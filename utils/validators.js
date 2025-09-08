
/**
 * validateEmail - Vérifie si une adresse email est bien formée
 * @param {string} email
 * @returns {boolean}
 */
export function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return typeof email === 'string' && regex.test(email);
  }
  
  /**
   * validateLinks - Vérifie que tous les liens sont valides (http/https)
   * @param {Array<string>} links
   * @returns {boolean}
   */
  export function validateLinks(links) {
    if (!Array.isArray(links)) return false;
    return links.every(link => typeof link === 'string' && /^https?:\/\//i.test(link));
  }
  
  /**
   * validateAttachments - Vérifie que les pièces jointes sont bien des chaînes
   * @param {Array<string>} attachments
   * @returns {boolean}
   */
  export function validateAttachments(attachments) {
    return Array.isArray(attachments) && attachments.every(a => typeof a === 'string');
  }
  
/**
 * validateSubject - Vérifie que le sujet est une chaîne non vide et raisonnable
 * @param {string} subject
 * @returns {boolean}
 */
export function validateSubject(subject) {
  return typeof subject === 'string' && subject.trim().length > 0 && subject.length <= 300;
}

/**
 * validateBody - Vérifie que le corps du mail est une chaîne non vide et raisonnable
 * @param {string} body
 * @returns {boolean}
 */
export function validateBody(body) {
  return typeof body === 'string' && body.trim().length > 0 && body.length <= 10000;
}

/**
 * validateEmailData - Vérifie la validité globale des données extraites
 * @param {Object} data
 * @returns {boolean}
 */
export function validateEmailData(data) {
  if (!data || typeof data !== 'object') return false;
  const { subject, body, sender, links, attachments } = data;
  return (
    validateSubject(subject) &&
    validateBody(body) &&
    validateEmail(sender) &&
    validateLinks(links) &&
    validateAttachments(attachments)
  );
}