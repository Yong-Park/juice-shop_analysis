import client from './elasticsearchClient';

async function logEvent(eventType: string, details: object): Promise<void> {
  const timestamp = new Date().toISOString();
  try {
    await client.index({
      index: 'logs',
      body: {
        eventType,
        details,
        timestamp
      }
    });
    console.log(`Log registrado: ${eventType}`);
  } catch (error) {
    console.error('Error al registrar el log en Elasticsearch:', error);
  }
}

export default logEvent;
