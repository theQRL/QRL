import os
import shutil
from qrl.core import config
from qrl.core.misc import db, logger
from qrl.core.State import State
from qrl.core.Block import Block


# TODO: State Migration integration pending
class StateMigration:
    def __init__(self):
        pass

    def state_migration_step_1(self, state: State) -> bool:
        """
        Migration Step from State Version 0 to 1
        :return:
        """
        if state.is_older_state_version():
            db_dir_v1 = os.path.join(config.user.data_dir, config.dev.db_name + '2')
            self._tmp_state = State(state._db)  # DB Pointing to Older State
            state._db = db.DB(db_dir_v1)  # DB Pointing to Newer State
            return True
        return False

    def height_from_state_version_0(self) -> int:
        return self._tmp_state.get_mainchain_height()

    def block_from_state_version_0(self, block_number):
        return Block.get_block_by_number(self._tmp_state, block_number)

    def state_migration_step_2(self, state: State):
        """
        Migration Step from State Version 0 to 1
        :return:
        """
        del self._tmp_state
        self._tmp_state = None
        del state._db

        tmp_db_dir = os.path.join(config.user.data_dir, config.dev.db_name + "3")
        db_dir = os.path.join(config.user.data_dir, config.dev.db_name)
        shutil.move(db_dir,
                    tmp_db_dir)
        tmp_db_dir = os.path.join(config.user.data_dir, config.dev.db_name + "2")
        shutil.move(tmp_db_dir,
                    db_dir)
        state._db = db.DB()
        logger.warning("State Migration Finished")
