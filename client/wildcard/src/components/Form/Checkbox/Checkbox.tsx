import classNames from 'classnames'
import React from 'react'

import { ControlInputProps } from '../internal/BaseControlInput'
import { getValidStyle } from '../internal/utils'

export type CheckboxProps = ControlInputProps

/**
 * Renders a single checkbox.
 *
 * Checkboxes should be used when a user can select any number of choices from a list of options.
 * They can often be used stand-alone, for a single option that a user can turn on or off.
 *
 * Grouped checkboxes should be visually presented together.
 *
 * Useful article comparing checkboxes to radio buttons: https://www.nngroup.com/articles/checkboxes-vs-radio-buttons/
 */
export const Checkbox: React.FunctionComponent<CheckboxProps> = React.forwardRef(
    ({ isValid, className, ...props }, reference) => (
        <input ref={reference} type="checkbox" className={classNames(getValidStyle(isValid), className)} {...props} />
    )
)
