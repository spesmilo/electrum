import os


class InheritedRecipeMixin:

    def get_recipe_dir(self):
        """This is used to replace pythonforandroid.recipe.Recipe.get_recipe_dir.
        If one of our local recipes inherits from a built-in p4a recipe, this override
        ensures that potential patches and other local files used by the recipe will
        be looked for in the built-in recipe's folder.
        """
        return os.path.join(self.ctx.root_dir, 'recipes', self.name)
