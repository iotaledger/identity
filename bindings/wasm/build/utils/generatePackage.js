module.exports = (options) => {
    const rootPackage = require(`../../${options.artifact}/package.json`);
    const newPackage = {
        name: rootPackage.name,
        description: rootPackage.description,
        version: rootPackage.version,
        license: rootPackage.license,
        homepage: rootPackage.homepage,
        repository: rootPackage.repository,
        module: options.module,
        main: options.main,
        types: options.types,
    };

    // remove empty keys
    Object.keys(newPackage).forEach(key => newPackage[key] === undefined && delete newPackage[key]);

    return newPackage;
};
