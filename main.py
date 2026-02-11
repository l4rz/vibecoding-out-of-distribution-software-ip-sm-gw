import asyncio
import yaml
from sip_frontend import start_sip_server
from registry import Registry

def load_config(path='config.yaml'):
    with open(path) as f:
        return yaml.safe_load(f)

async def main():
    config = load_config()
    registry = Registry(config['registry']['db_path'])
    await registry.init_db()
    await start_sip_server(config, registry)

if __name__ == '__main__':
    asyncio.run(main()) 